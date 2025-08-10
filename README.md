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

- 📤 **Exfiltration Support**
  - Uploads retrieved data (S3 objects, secrets, DynamoDB dumps) to Dropbox (App Folder scope)

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
