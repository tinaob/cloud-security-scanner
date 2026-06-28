import boto3
import json
import os
from datetime import datetime, timezone

# ============================================
# CIS BENCHMARK MAPPING
# Maps each check to its CIS AWS Foundations
# Benchmark control number
# ============================================
CIS_MAPPING = {
    "Root Account MFA":         "CIS 1.5  — Enable MFA for root account",
    "Root Account Usage":       "CIS 1.7  — Eliminate use of root account",
    "IAM User MFA":             "CIS 1.10 — Enable MFA for all IAM users",
    "Access Key Age":           "CIS 1.14 — Rotate access keys every 90 days",
    "S3 Public Access":         "CIS 2.1  — Ensure S3 bucket not publicly accessible",
    "IAM Admin Policy":         "CIS 1.16 — Ensure IAM policies not attached directly",
    "Security Group":           "CIS 5.2  — No security groups allow 0.0.0.0/0 on sensitive ports",
    "S3 Encryption":            "CIS 2.2  — Ensure S3 buckets have encryption enabled",
}

# ============================================
# REMEDIATION RECOMMENDATIONS
# Specific fix instructions for each check
# ============================================
REMEDIATION = {
    "Root Account MFA":
        "Go to AWS Console → IAM → Security credentials → "
        "Activate MFA. Use a virtual MFA app like Google Authenticator.",

    "Root Account Usage":
        "Create an IAM user with appropriate permissions for daily tasks. "
        "Only use root for account-level tasks that require it.",

    "IAM User MFA":
        "Go to IAM → Users → Select user → Security credentials → "
        "Assign MFA device. Enforce MFA using an IAM policy.",

    "Access Key Age":
        "Go to IAM → Users → Security credentials → Create new access key, "
        "update all applications using the old key, then deactivate and delete the old key.",

    "S3 Public Access":
        "Go to S3 → Select bucket → Permissions → Block public access → "
        "Enable all four block public access settings.",

    "IAM Admin Policy":
        "Remove AdministratorAccess from IAM users directly. "
        "Instead create an IAM group with required permissions and add users to the group.",

    "Security Group":
        "Go to EC2 → Security Groups → Edit inbound rules → "
        "Replace 0.0.0.0/0 source with specific IP ranges or security group IDs.",

    "S3 Encryption":
        "Go to S3 → Select bucket → Properties → Default encryption → "
        "Enable with SSE-S3 or SSE-KMS encryption.",
}

# ============================================
# RISK SCORING
# Each finding type has a base risk score
# ============================================
RISK_SCORES = {
    "HIGH":   30,
    "MEDIUM": 15,
    "LOW":     5,
    "NONE":    0,
}

# ============================================
# STEP 1: Connect to AWS
# ============================================
def connect_to_aws():
    print("\n" + "=" * 60)
    print("   AWS CLOUD SECURITY ASSESSMENT TOOL v2.0")
    print("=" * 60)
    print("\n🔌 Connecting to AWS...\n")

    try:
        session = boto3.Session()
        iam = session.client('iam')
        s3 = session.client('s3')
        ec2 = session.client('ec2', region_name='eu-west-1')

        iam.get_account_summary()
        print("✅ Connected to AWS successfully!\n")
        return iam, s3, ec2

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return None, None, None

# ============================================
# STEP 2: Check root account
# ============================================
def check_root_account(iam):
    print("=" * 60)
    print("CHECK 1: Root Account Security [CIS 1.5 & 1.7]")
    print("=" * 60)

    findings = []

    try:
        try:
            iam.generate_credential_report()
        except:
            pass

        import time
        time.sleep(3)

        report = iam.get_credential_report()
        content = report['Content'].decode('utf-8')
        lines = content.strip().split('\n')

        for line in lines[1:]:
            fields = line.split(',')
            if fields[0] == '<root_account>':
                root_mfa = fields[7]
                root_last_used = fields[4]

                if root_mfa == 'false':
                    print("🔴 HIGH: Root account has NO MFA enabled!")
                    print(f"   CIS: {CIS_MAPPING['Root Account MFA']}")
                    print(f"   Fix: {REMEDIATION['Root Account MFA']}\n")
                    findings.append(make_finding(
                        "Root Account MFA", "FAIL", "HIGH",
                        "Root account MFA is not enabled"
                    ))
                else:
                    print("✅ PASS: Root account MFA is enabled")
                    findings.append(make_finding(
                        "Root Account MFA", "PASS", "NONE",
                        "Root account MFA is enabled"
                    ))

                if root_last_used not in ['N/A', 'no_information', '']:
                    print(f"🟡 MEDIUM: Root account was used: {root_last_used}")
                    print(f"   CIS: {CIS_MAPPING['Root Account Usage']}")
                    print(f"   Fix: {REMEDIATION['Root Account Usage']}\n")
                    findings.append(make_finding(
                        "Root Account Usage", "FAIL", "MEDIUM",
                        f"Root account was used on {root_last_used}"
                    ))
                else:
                    print("✅ PASS: Root account not used recently\n")
                    findings.append(make_finding(
                        "Root Account Usage", "PASS", "NONE",
                        "Root account has not been used recently"
                    ))

    except Exception as e:
        print(f"⚠️  Could not check root account: {e}\n")

    return findings

# ============================================
# STEP 3: Check IAM MFA
# ============================================
def check_iam_mfa(iam):
    print("=" * 60)
    print("CHECK 2: IAM Users Without MFA [CIS 1.10]")
    print("=" * 60)

    findings = []

    try:
        users = iam.list_users()['Users']
        print(f"Found {len(users)} IAM users\n")

        for user in users:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(
                UserName=username
            )['MFADevices']

            if len(mfa_devices) == 0:
                print(f"🔴 HIGH: User '{username}' has NO MFA!")
                print(f"   CIS: {CIS_MAPPING['IAM User MFA']}")
                print(f"   Fix: {REMEDIATION['IAM User MFA']}\n")
                findings.append(make_finding(
                    "IAM User MFA", "FAIL", "HIGH",
                    f"User {username} has no MFA device"
                ))
            else:
                print(f"✅ PASS: User '{username}' has MFA enabled")
                findings.append(make_finding(
                    "IAM User MFA", "PASS", "NONE",
                    f"User {username} has MFA enabled"
                ))

    except Exception as e:
        print(f"⚠️  Could not check MFA: {e}\n")

    print()
    return findings

# ============================================
# STEP 4: Check access key age
# ============================================
def check_old_access_keys(iam):
    print("=" * 60)
    print("CHECK 3: Access Key Rotation [CIS 1.14]")
    print("=" * 60)

    findings = []

    try:
        users = iam.list_users()['Users']

        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(
                UserName=username
            )['AccessKeyMetadata']

            for key in keys:
                created = key['CreateDate']
                now = datetime.now(timezone.utc)
                age_days = (now - created).days
                key_id = key['AccessKeyId']
                status = key['Status']

                if age_days > 90 and status == 'Active':
                    print(f"🔴 HIGH: User '{username}' key is {age_days} days old!")
                    print(f"   CIS: {CIS_MAPPING['Access Key Age']}")
                    print(f"   Fix: {REMEDIATION['Access Key Age']}\n")
                    findings.append(make_finding(
                        "Access Key Age", "FAIL", "HIGH",
                        f"User {username} key {key_id} is {age_days} days old"
                    ))
                elif age_days > 90 and status == 'Inactive':
                    print(f"🟡 LOW: User '{username}' has old inactive key")
                    findings.append(make_finding(
                        "Access Key Age", "WARN", "LOW",
                        f"User {username} inactive key is {age_days} days old"
                    ))
                else:
                    print(f"✅ PASS: User '{username}' key is {age_days} days old")
                    findings.append(make_finding(
                        "Access Key Age", "PASS", "NONE",
                        f"User {username} key is {age_days} days old"
                    ))

    except Exception as e:
        print(f"⚠️  Could not check access keys: {e}\n")

    print()
    return findings

# ============================================
# STEP 5: Check S3 public access
# ============================================
def check_s3_public_access(s3):
    print("=" * 60)
    print("CHECK 4: S3 Public Access [CIS 2.1]")
    print("=" * 60)

    findings = []

    try:
        buckets = s3.list_buckets()['Buckets']

        if len(buckets) == 0:
            print("✅ PASS: No S3 buckets found\n")
            findings.append(make_finding(
                "S3 Public Access", "PASS", "NONE",
                "No S3 buckets exist in this account"
            ))
            return findings

        print(f"Found {len(buckets)} S3 buckets\n")

        for bucket in buckets:
            bucket_name = bucket['Name']

            try:
                public_access = s3.get_public_access_block(
                    Bucket=bucket_name
                )
                config = public_access['PublicAccessBlockConfiguration']

                all_blocked = all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ])

                if all_blocked:
                    print(f"✅ PASS: Bucket '{bucket_name}' is private")
                    findings.append(make_finding(
                        "S3 Public Access", "PASS", "NONE",
                        f"Bucket {bucket_name} blocks all public access"
                    ))
                else:
                    print(f"🔴 HIGH: Bucket '{bucket_name}' may be public!")
                    print(f"   CIS: {CIS_MAPPING['S3 Public Access']}")
                    print(f"   Fix: {REMEDIATION['S3 Public Access']}\n")
                    findings.append(make_finding(
                        "S3 Public Access", "FAIL", "HIGH",
                        f"Bucket {bucket_name} does not block public access"
                    ))

            except Exception:
                print(f"🔴 HIGH: Bucket '{bucket_name}' has no access block!")
                print(f"   Fix: {REMEDIATION['S3 Public Access']}\n")
                findings.append(make_finding(
                    "S3 Public Access", "FAIL", "HIGH",
                    f"Bucket {bucket_name} has no public access block"
                ))

    except Exception as e:
        print(f"⚠️  Could not check S3: {e}\n")

    print()
    return findings

# ============================================
# STEP 6: NEW — Check IAM admin policies
# ============================================
def check_iam_admin_policies(iam):
    print("=" * 60)
    print("CHECK 5: Overly Permissive IAM Policies [CIS 1.16]")
    print("=" * 60)

    findings = []

    try:
        users = iam.list_users()['Users']

        for user in users:
            username = user['UserName']
            attached = iam.list_attached_user_policies(
                UserName=username
            )['AttachedPolicies']

            for policy in attached:
                policy_name = policy['PolicyName']

                if policy_name == 'AdministratorAccess':
                    print(f"🔴 HIGH: User '{username}' has AdministratorAccess!")
                    print(f"   CIS: {CIS_MAPPING['IAM Admin Policy']}")
                    print(f"   Fix: {REMEDIATION['IAM Admin Policy']}\n")
                    findings.append(make_finding(
                        "IAM Admin Policy", "FAIL", "HIGH",
                        f"User {username} has AdministratorAccess attached directly"
                    ))
                elif 'FullAccess' in policy_name:
                    print(f"🟡 MEDIUM: User '{username}' has {policy_name}")
                    print(f"   Consider replacing with least-privilege policy\n")
                    findings.append(make_finding(
                        "IAM Admin Policy", "WARN", "MEDIUM",
                        f"User {username} has broad policy: {policy_name}"
                    ))
                else:
                    print(f"✅ PASS: User '{username}' policy '{policy_name}' — OK")
                    findings.append(make_finding(
                        "IAM Admin Policy", "PASS", "NONE",
                        f"User {username} has appropriate policy: {policy_name}"
                    ))

    except Exception as e:
        print(f"⚠️  Could not check IAM policies: {e}\n")

    print()
    return findings

# ============================================
# STEP 7: NEW — Check security groups
# ============================================
def check_security_groups(ec2):
    print("=" * 60)
    print("CHECK 6: Security Groups Open to Internet [CIS 5.2]")
    print("=" * 60)

    findings = []
    dangerous_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        1433: "MSSQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
    }

    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        print(f"Found {len(sgs)} security groups\n")

        for sg in sgs:
            sg_name = sg['GroupName']
            sg_id = sg['GroupId']

            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)

                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')

                    if cidr == '0.0.0.0/0':
                        if from_port in dangerous_ports:
                            service = dangerous_ports[from_port]
                            print(f"🔴 HIGH: Security group '{sg_name}' ({sg_id})")
                            print(f"   Port {from_port} ({service}) open to ALL internet!")
                            print(f"   CIS: {CIS_MAPPING['Security Group']}")
                            print(f"   Fix: {REMEDIATION['Security Group']}\n")
                            findings.append(make_finding(
                                "Security Group", "FAIL", "HIGH",
                                f"SG {sg_name} exposes port {from_port} ({service}) to 0.0.0.0/0"
                            ))
                        elif from_port == 0 and to_port == 65535:
                            print(f"🔴 HIGH: Security group '{sg_name}' opens ALL ports!")
                            findings.append(make_finding(
                                "Security Group", "FAIL", "HIGH",
                                f"SG {sg_name} opens all ports to 0.0.0.0/0"
                            ))
                        else:
                            print(f"🟡 MEDIUM: SG '{sg_name}' port {from_port} open to internet")
                            findings.append(make_finding(
                                "Security Group", "WARN", "MEDIUM",
                                f"SG {sg_name} port {from_port} open to 0.0.0.0/0"
                            ))

        if not findings:
            print("✅ PASS: No dangerous security group rules found\n")
            findings.append(make_finding(
                "Security Group", "PASS", "NONE",
                "No security groups expose dangerous ports to the internet"
            ))

    except Exception as e:
        print(f"⚠️  Could not check security groups: {e}\n")

    print()
    return findings

# ============================================
# STEP 8: NEW — Check S3 encryption
# ============================================
def check_s3_encryption(s3):
    print("=" * 60)
    print("CHECK 7: S3 Bucket Encryption [CIS 2.2]")
    print("=" * 60)

    findings = []

    try:
        buckets = s3.list_buckets()['Buckets']

        if len(buckets) == 0:
            print("✅ PASS: No S3 buckets to check\n")
            return findings

        for bucket in buckets:
            bucket_name = bucket['Name']

            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption['ServerSideEncryptionConfiguration']['Rules']
                enc_type = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                print(f"✅ PASS: Bucket '{bucket_name}' encrypted with {enc_type}")
                findings.append(make_finding(
                    "S3 Encryption", "PASS", "NONE",
                    f"Bucket {bucket_name} uses {enc_type} encryption"
                ))

            except Exception:
                print(f"🔴 HIGH: Bucket '{bucket_name}' has NO encryption!")
                print(f"   CIS: {CIS_MAPPING['S3 Encryption']}")
                print(f"   Fix: {REMEDIATION['S3 Encryption']}\n")
                findings.append(make_finding(
                    "S3 Encryption", "FAIL", "HIGH",
                    f"Bucket {bucket_name} has no default encryption"
                ))

    except Exception as e:
        print(f"⚠️  Could not check S3 encryption: {e}\n")

    print()
    return findings

# ============================================
# HELPER: Create a standard finding object
# ============================================
def make_finding(check, status, risk, detail):
    return {
        "check": check,
        "status": status,
        "risk": risk,
        "detail": detail,
        "cis_control": CIS_MAPPING.get(check, "N/A"),
        "remediation": REMEDIATION.get(check, "See AWS documentation")
    }

# ============================================
# STEP 9: Calculate risk score
# ============================================
def calculate_risk_score(findings):
    total_deductions = sum(
        RISK_SCORES.get(f['risk'], 0)
        for f in findings
        if f['status'] in ['FAIL', 'WARN']
    )
    score = max(0, 100 - total_deductions)
    return score

# ============================================
# STEP 10: Generate HTML dashboard
# ============================================
def generate_html_dashboard(findings, score):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    high = [f for f in findings if f['risk'] == 'HIGH' and f['status'] == 'FAIL']
    medium = [f for f in findings if f['risk'] == 'MEDIUM']
    low = [f for f in findings if f['risk'] == 'LOW']
    passed = [f for f in findings if f['status'] == 'PASS']

    if score >= 80:
        score_color = "#27ae60"
        score_label = "GOOD"
    elif score >= 60:
        score_color = "#f39c12"
        score_label = "MODERATE"
    else:
        score_color = "#e74c3c"
        score_label = "POOR"

    findings_rows = ""
    for f in findings:
        if f['risk'] == 'HIGH' and f['status'] == 'FAIL':
            risk_badge = '<span style="background:#e74c3c;color:white;padding:3px 8px;border-radius:4px;font-size:12px;">HIGH</span>'
        elif f['risk'] == 'MEDIUM':
            risk_badge = '<span style="background:#f39c12;color:white;padding:3px 8px;border-radius:4px;font-size:12px;">MEDIUM</span>'
        elif f['risk'] == 'LOW':
            risk_badge = '<span style="background:#3498db;color:white;padding:3px 8px;border-radius:4px;font-size:12px;">LOW</span>'
        else:
            risk_badge = '<span style="background:#27ae60;color:white;padding:3px 8px;border-radius:4px;font-size:12px;">PASS</span>'

        status_icon = "✅" if f['status'] == 'PASS' else "🔴" if f['risk'] == 'HIGH' else "⚠️"

        findings_rows += f"""
        <tr>
            <td>{status_icon} {f['check']}</td>
            <td>{risk_badge}</td>
            <td>{f['detail']}</td>
            <td style="font-size:12px;color:#666;">{f['cis_control']}</td>
            <td style="font-size:12px;">{f['remediation'][:80]}...</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AWS Cloud Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f6fa; }}
        .header {{ background: #2c3e50; color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .header p {{ margin: 5px 0 0; color: #bdc3c7; }}
        .score-box {{ background: white; border-radius: 8px; padding: 30px; text-align: center; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .score-number {{ font-size: 72px; font-weight: bold; color: {score_color}; }}
        .score-label {{ font-size: 18px; color: {score_color}; font-weight: bold; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card-number {{ font-size: 36px; font-weight: bold; }}
        .card-label {{ font-size: 14px; color: #666; margin-top: 5px; }}
        .high {{ color: #e74c3c; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .pass {{ color: #27ae60; }}
        .table-box {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; font-size: 13px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #ecf0f1; font-size: 13px; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>☁️ AWS Cloud Security Assessment Report</h1>
        <p>Generated: {timestamp} | Tool: Cloud Security Assessment Tool v2.0</p>
        <p>Built by Clementina Obasi — Cybersecurity Portfolio Project</p>
    </div>

    <div class="score-box">
        <div class="score-number">{score}/100</div>
        <div class="score-label">Security Score — {score_label}</div>
        <p style="color:#666;margin-top:10px;">Based on CIS AWS Foundations Benchmark controls</p>
    </div>

    <div class="cards">
        <div class="card">
            <div class="card-number high">{len(high)}</div>
            <div class="card-label">High Risk</div>
        </div>
        <div class="card">
            <div class="card-number medium">{len(medium)}</div>
            <div class="card-label">Medium Risk</div>
        </div>
        <div class="card">
            <div class="card-number low">{len(low)}</div>
            <div class="card-label">Low Risk</div>
        </div>
        <div class="card">
            <div class="card-number pass">{len(passed)}</div>
            <div class="card-label">Passed</div>
        </div>
    </div>

    <div class="table-box">
        <h2 style="margin-top:0;">Detailed Findings</h2>
        <table>
            <tr>
                <th>Check</th>
                <th>Risk</th>
                <th>Detail</th>
                <th>CIS Control</th>
                <th>Remediation</th>
            </tr>
            {findings_rows}
        </table>
    </div>

    <div class="footer">
        <p>AWS Cloud Security Assessment Tool v2.0 | 
        Built as part of Clementina Obasi's Cybersecurity Portfolio | 
        github.com/tinaob/cloud-security-scanner</p>
    </div>
</body>
</html>
    """

    filename = f"security_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"🌐 HTML Dashboard saved to: {filename}")
    return filename

# ============================================
# STEP 11: Save JSON report
# ============================================
def save_json_report(findings, score):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cloud_security_report_{timestamp}.json"

    high = [f for f in findings if f['risk'] == 'HIGH' and f['status'] == 'FAIL']
    medium = [f for f in findings if f['risk'] == 'MEDIUM']
    passed = [f for f in findings if f['status'] == 'PASS']

    with open(filename, 'w') as f:
        json.dump({
            "scan_date": timestamp,
            "tool": "Cloud Security Assessment Tool v2.0",
            "security_score": score,
            "summary": {
                "total_checks": len(findings),
                "high_risk": len(high),
                "medium_risk": len(medium),
                "passed": len(passed)
            },
            "findings": findings
        }, f, indent=4)

    print(f"📄 JSON Report saved to: {filename}")
    return filename

# ============================================
# STEP 12: Show final summary
# ============================================
def show_summary(findings, score):
    high = [f for f in findings if f['risk'] == 'HIGH' and f['status'] == 'FAIL']
    medium = [f for f in findings if f['risk'] == 'MEDIUM']
    low = [f for f in findings if f['risk'] == 'LOW']
    passed = [f for f in findings if f['status'] == 'PASS']

    print("\n" + "=" * 60)
    print("   SECURITY ASSESSMENT SUMMARY")
    print("=" * 60)

    if score >= 80:
        print(f"🟢 Security Score: {score}/100 — GOOD")
    elif score >= 60:
        print(f"🟡 Security Score: {score}/100 — MODERATE")
    else:
        print(f"🔴 Security Score: {score}/100 — POOR")

    print(f"\nTotal checks:  {len(findings)}")
    print(f"Passed:        {len(passed)}")
    print(f"High Risk:     {len(high)}")
    print(f"Medium Risk:   {len(medium)}")
    print(f"Low Risk:      {len(low)}")

    if high:
        print("\n🚨 IMMEDIATE ACTION REQUIRED:")
        for f in high:
            print(f"  [{f['cis_control']}]")
            print(f"   {f['detail']}")
            print(f"   Fix: {f['remediation'][:70]}...")

    print("\n" + "=" * 60)
    print("   SCAN COMPLETE")
    print("=" * 60 + "\n")

# ============================================
# MAIN: Run everything
# ============================================
def main():
    iam, s3, ec2 = connect_to_aws()

    if not iam:
        return

    all_findings = []
    all_findings += check_root_account(iam)
    all_findings += check_iam_mfa(iam)
    all_findings += check_old_access_keys(iam)
    all_findings += check_s3_public_access(s3)
    all_findings += check_iam_admin_policies(iam)
    all_findings += check_security_groups(ec2)
    all_findings += check_s3_encryption(s3)

    score = calculate_risk_score(all_findings)
    show_summary(all_findings, score)
    save_json_report(all_findings, score)
    generate_html_dashboard(all_findings, score)

main()