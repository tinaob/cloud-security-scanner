# AWS Cloud Security Misconfiguration Scanner ☁️🔍

A Python tool that automatically audits AWS accounts for common 
security misconfigurations that lead to real-world data breaches.

---

## ⚠️ Legal Warning

Only scan AWS accounts you own or have explicit written permission 
to audit. Unauthorized scanning of cloud accounts is illegal.

---

## What Problem Does This Solve?

Cloud misconfiguration is the number one cause of data breaches 
in 2024-2026. Companies like Capital One, Facebook, and Toyota 
have suffered major breaches due to misconfigured cloud resources. 
This tool automates the security audit process, instantly flagging 
misconfigurations that could expose sensitive data or allow 
unauthorized access.

---

## What It Checks

- **Root account MFA** — detects if the all-powerful root account lacks MFA
- **Root account usage** — flags if root account has been used recently
- **IAM users without MFA** — identifies user accounts with no two-factor authentication
- **Old access keys** — detects API keys older than 90 days that should be rotated
- **Public S3 buckets** — finds storage buckets exposed to the entire internet
- **Auto-generates JSON report** — timestamped report for audit documentation

---

## Real Findings From My Own AWS Account

When I ran this tool against my own AWS account it found:

- **Root account used today** — flagged as medium risk. Even though 
  MFA was enabled, using root for any task violates AWS security 
  best practices
- **2 IAM users without MFA** — both the security-scanner service 
  account and my personal IAM user lacked MFA devices, which the 
  tool correctly flagged as high risk

These are real misconfigurations in a real AWS account — 
demonstrating the tool works as intended.

---

## Example Output

---

## Tools and Technologies Used

| Tool | Purpose |
|---|---|
| Python 3 | Core programming language |
| boto3 | AWS SDK for Python — connects to AWS APIs |
| AWS IAM | Identity and Access Management scanning |
| AWS S3 | Storage bucket public access checking |
| AWS CLI | Authentication and credential management |
| JSON | Structured report output |
| datetime | Timestamping reports |

---

## How to Run It Yourself

### 1. Create a free AWS account
Sign up at aws.amazon.com/free

### 2. Create an IAM user with ReadOnlyAccess
Never use your root account for scanning

### 3. Install AWS CLI
Download from docs.aws.amazon.com/cli

### 4. Configure your credentials

### 5. Clone this repository

### 6. Install Python dependency

### 7. Run the scanner

---

## What I Learned Building This

- How to connect Python to AWS using boto3 and IAM credentials
- Why cloud misconfiguration causes more breaches than hacking — 
  it is easier to find an open door than to break one down
- How MFA protects accounts even when passwords are compromised
- Why root account usage is dangerous — it bypasses all permission 
  boundaries and leaves no granular audit trail
- How access key rotation reduces the window of exposure if keys 
  are stolen
- The principle of least privilege in practice — our scanner itself 
  uses ReadOnlyAccess, meaning even if its credentials were stolen 
  an attacker could only read, never modify or delete

---

## Limitations and Future Improvements

- Currently checks 4 misconfiguration types — production version 
  would check 50+ using AWS Security Hub standards
- Does not yet check Security Groups for overly permissive rules 
  (0.0.0.0/0 on sensitive ports)
- Could integrate with AWS Config for continuous monitoring rather 
  than point-in-time scanning
- Future version will add email alerting when critical 
  misconfigurations are detected
- Could expand to check CloudTrail logging, VPC flow logs, 
  and encryption settings

---

## Author

**Clementina Obasi**
Cybersecurity Analyst | CySA+ | CCNA CyberOps | Google Cybersecurity Certified
[LinkedIn](https://www.linkedin.com/in/clementina-obasi-b89a3381/)

---

*Built as part of my cybersecurity portfolio — June 2026*
