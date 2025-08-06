import os
import dropbox
import configparser
import boto3
from botocore.exceptions import ClientError

# Local folder to save downloaded files
LOCAL_DOWNLOAD_DIR = 'upload'

# Make sure the directory exists
os.makedirs(LOCAL_DOWNLOAD_DIR, exist_ok=True)

# Initialize S3 client (relies on AWS credentials)
s3 = boto3.client('s3')

try:
    # List all buckets
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets']]
except ClientError as e:
    print(f"❌ Failed to list S3 buckets: {e}")
    buckets = []

print(f"🪣 Found {len(buckets)} buckets.")

# Loop through each bucket and list/download objects
for bucket in buckets:
    print(f"\n📂 Accessing bucket: {bucket}")
    try:
        objects = s3.list_objects_v2(Bucket=bucket)

        if 'Contents' not in objects:
            print(f"   (Empty or no access to list contents.)")
            continue

        for obj in objects['Contents']:
            key = obj['Key']
            local_path = os.path.join(LOCAL_DOWNLOAD_DIR, os.path.basename(key))

            try:
                print(f"   ⬇ Downloading {key} -> {local_path}")
                s3.download_file(bucket, key, local_path)
            except ClientError as download_err:
                print(f"   ❌ Failed to download {key}: {download_err}")

    except ClientError as list_err:
        print(f"   ❌ Cannot list objects in {bucket}: {list_err}")

# Read from config.ini
config = configparser.ConfigParser()
config.read('config.ini')
ACCESS_TOKEN = config['dropbox']['access_token']

# Local directory to upload
LOCAL_DIR = 'upload'

# Connect to Dropbox
dbx = dropbox.Dropbox(ACCESS_TOKEN)

# Walk through the local folder
for root, dirs, files in os.walk(LOCAL_DIR):
    for filename in files:
        local_path = os.path.join(root, filename)
        dropbox_path = '/' + filename

        with open(local_path, 'rb') as f:
            print(f"Uploading {local_path} to Dropbox at {dropbox_path}...")
            dbx.files_upload(f.read(), dropbox_path, mode=dropbox.files.WriteMode.add)

print("✅ All files uploaded.")
