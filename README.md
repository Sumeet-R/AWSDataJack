# AWSDataJack

**AWSDataJack** is a modular cloud attack simulation framework built to evaluate the detection and response capabilities of Security Operations Centers (SOCs), Cloud Native Application Protection Platforms (CNAPPs), and other cloud security tools.

It simulates realistic cloud data exfiltration scenarios by targeting misconfigured or over-permissive AWS services and attempting to extract data to external destinations.

---

## 🎯 Use Case

AWSDataJack is intended for **security testing and validation** in authorized environments.  
It helps you:

- Test the **permissions of an EC2 instance profile** attached to a running instance.
- Identify excessive privileges that could enable unauthorized data access.
- Validate detection and alerting coverage for suspicious AWS API activity.

> ⚠️ **Disclaimer:** This tool must **never** be used against assets without explicit permission.

---

## ✅ Current Capabilities

- 🪣 **S3 Module**
  - Lists all accessible buckets
  - Enumerates and downloads objects from exposed or misconfigured buckets

- 🔐 **AWS Secrets Manager Module**
  - Enumerates all secrets in the configured AWS region
  - Retrieves and stores secret values (if accessible)

- 🗄️ **DynamoDB Module**
  - Lists all accessible DynamoDB tables
  - Dumps all items from each table

- 🌐 **Nmap Network Recon Module**
  - Automatically detects local subnet from host
  - Scans for well-known service ports (HTTP, HTTPS, SSH, FTP, RDP, SMTP, and more)
  - Lists all live hosts and open ports in the network
  - Saves scan results in `upload/` directory

- 📤 **Exfiltration Support**
  - Uploads retrieved data (S3 objects, secrets, DynamoDB dumps, Nmap results) to Dropbox (App Folder scope)

---

## 🛠️ Coming Soon

- 💾 EBS snapshot enumeration and download
- 🐘 RDS snapshot access and export
- 🔑 KMS key detection & `kms:ViaService` policy suggestions
- 📊 Detection mapping to MITRE ATT&CK and cloud-native alerts

---

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Sumeet-R/AWSDataJack.git
cd AWSDataJack
```

### 2. Configure Dropbox Access and AWS Region
Edit `config.ini` to include your AWS region and Dropbox access token:

```ini
[aws]
region = YOUR_AWS_REGION

[dropbox]
access_token = YOUR_DROPBOX_ACCESS_TOKEN
```

- Create a Dropbox App [here](https://www.dropbox.com/developers/apps)  
- Set scope to: **App Folder**  
- Generate and copy the access token  

```bash
nano config.ini
```

### 3. Run the Installer
```bash
sudo bash installer.sh
```

This will:
- Install Python 3 and pip  
- Install required Python packages (`dropbox`, `boto3`, `configparser`, `python-nmap`, `psutil`)  
- Create the `upload/` directory  
- Run the script once  
- Schedule it via `cron` to run daily at **23:30**  

---

## 📄 Output

- All retrieved files and dumps are saved in the `upload/` directory.  
- The directory is uploaded to Dropbox after each run.  
- `awsdatajack.log` stores run logs for review.

---

## 🔍 Detection Expectations

When AWSDataJack runs, it will generate AWS CloudTrail events and possible network activity logs that SOC teams and CNAPPs can detect. Examples:

| Module                | Example API Calls / Activity                           |
|-----------------------|--------------------------------------------------------|
| S3                    | `ListBuckets`, `ListObjectsV2`, `GetObject`            |
| Secrets Manager       | `ListSecrets`, `GetSecretValue`                         |
| DynamoDB              | `ListTables`, `Scan`                                   |
| Nmap Network Recon    | Network scans for open ports and live hosts             |
| Dropbox Exfiltration  | *No CloudTrail events – external network activity only* |

Security teams should look for:
- Unexpected data access patterns
- Access from unusual IPs or instance profiles
- Large-volume `GetObject` or `Scan` operations
- `GetSecretValue` calls from unexpected principals
- Internal network scanning activity

---

## ⚠️ Legal Disclaimer

This tool is intended **only** for authorized environments such as lab setups or sanctioned red team assessments.  
You are responsible for complying with all applicable laws and regulations.  
Unauthorized use is strictly prohibited.

---
