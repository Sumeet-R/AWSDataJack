# AWSDataJack

**AWSDataJack** is a modular cloud attack simulation framework built to evaluate the detection and response capabilities of Security Operations Centers (SOCs), Cloud Native Application Protection Platforms (CNAPPs), and other cloud security tools.

It simulates realistic cloud exfiltration scenarios by targeting misconfigured or over-permissive AWS services and attempting to extract data to external destinations.

## 🎯 Use Case

AWSDataJack is not designed for offensive operations, but rather to **test and benchmark cloud security tooling**, visibility, and alerting coverage against common misconfigurations and data leakage paths.

## ✅ Current Capabilities

- 🪣 **S3 Module**:  
  - Lists buckets
  - Enumerates accessible objects
  - Downloads data from exposed or misconfigured buckets

- 📤 **Exfiltration Support**:  
  - Uploads stolen data to Dropbox (App Folder scope)

## 🛠 Coming Soon

- 💾 EBS snapshot enumeration and download
- 🐘 RDS snapshot access and export
- 🔐 AWS Secrets Manager dump simulation
- 📊 Detection mapping to MITRE ATT&CK and cloud-native alerts

## ⚠️ Disclaimer

> This tool is intended **only** for authorized environments such as lab setups or sanctioned red team assessments. It must **never** be used against assets you do not have explicit permission to test.

---
