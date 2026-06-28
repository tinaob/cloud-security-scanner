import boto3
import json
from datetime import datetime, timezone

# ============================================
# STEP 1: Connect to AWS
# ============================================
def connect_to_aws():
    print("\n" + "=" * 55)
    print("   AWS CLOUD SECURITY MISCONFIGURATION SCANNER")
    print("=" * 55)
    print("\n🔌 Connecting to AWS...\n")

    try:
        # This uses the credentials you set up with aws configure
        session = boto3.Session()
        iam = session.client('iam')
        s3 = session.client('s3')

        # Test connection
        iam.get_account_summary()
        print("✅ Connected to AWS successfully!\n")
        return iam, s3

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("Make sure you ran 'aws configure' correctly")
        return None, None

# ============================================
# STEP 2: Check if root account was used recently
# ============================================
def check_root_account(iam):
    print("=" * 55)
    print("CHECK 1: Root Account Usage")
    print("=" * 55)

    try:
        summary = iam.get_account_summary()
        account_mfa = summary['SummaryMap'].get('AccountMFAEnabled', 0)

        # Get credential report for root usage
        try:
            iam.generate_credential_report()
        except:
            pass

        import time
        time.sleep(3)

        report = iam.get_credential_report()
        content = report['Content'].decode('utf-8')
        lines = content.strip().split('\n')

        findings = []

        for line in lines[1:]:
            fields = line.split(',')
            if fields[0] == '<root_account>':
                root_mfa = fields[7]
                root_last_used = fields[4]

                if root_mfa == 'false':
                    print("🔴 HIGH RISK: Root account does NOT have MFA enabled!")
                    print("   Fix: Enable MFA on root account immediately")
                    findings.append({
                        "check": "Root Account MFA",
                        "status": "FAIL",
                        "risk": "HIGH",
                        "detail": "Root account MFA is not enabled"
                    })
                else:
                    print("✅ Root account MFA is enabled")
                    findings.append({
                        "check": "Root Account MFA",
                        "status": "PASS",
                        "risk": "NONE",
                        "detail": "Root account MFA is enabled"
                    })

                if root_last_used != 'N/A' and root_last_used != 'no_information':
                    print(f"⚠️  WARNING: Root account was last used: {root_last_used}")
                    print("   Fix: Never use root account for daily tasks")
                    findings.append({
                        "check": "Root Account Usage",
                        "status": "FAIL",
                        "risk": "MEDIUM",
                        "detail": f"Root account was used on {root_last_used}"
                    })
                else:
                    print("✅ Root account has not been used recently")
                    findings.append({
                        "check": "Root Account Usage",
                        "status": "PASS",
                        "risk": "NONE",
                        "detail": "Root account has not been used recently"
                    })

        print()
        return findings

    except Exception as e:
        print(f"⚠️  Could not check root account: {e}\n")
        return []

# ============================================
# STEP 3: Check IAM users for MFA
# ============================================
def check_iam_mfa(iam):
    print("=" * 55)
    print("CHECK 2: IAM Users Without MFA")
    print("=" * 55)

    findings = []

    try:
        users = iam.list_users()['Users']
        print(f"Found {len(users)} IAM users\n")

        for user in users:
            username = user['UserName']
            mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']

            if len(mfa_devices) == 0:
                print(f"🔴 HIGH RISK: User '{username}' has NO MFA enabled!")
                print(f"   Fix: Enable MFA for {username} immediately")
                findings.append({
                    "check": "IAM User MFA",
                    "status": "FAIL",
                    "risk": "HIGH",
                    "detail": f"User {username} has no MFA device"
                })
            else:
                print(f"✅ User '{username}' has MFA enabled")
                findings.append({
                    "check": "IAM User MFA",
                    "status": "PASS",
                    "risk": "NONE",
                    "detail": f"User {username} has MFA enabled"
                })

        print()
        return findings

    except Exception as e:
        print(f"⚠️  Could not check MFA: {e}\n")
        return []

# ============================================
# STEP 4: Check for old access keys
# ============================================
def check_old_access_keys(iam):
    print("=" * 55)
    print("CHECK 3: Old Access Keys (older than 90 days)")
    print("=" * 55)

    findings = []

    try:
        users = iam.list_users()['Users']

        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

            for key in keys:
                created = key['CreateDate']
                now = datetime.now(timezone.utc)
                age_days = (now - created).days
                key_id = key['AccessKeyId']
                status = key['Status']

                if age_days > 90 and status == 'Active':
                    print(f"🔴 HIGH RISK: User '{username}' has an active")
                    print(f"   access key {key_id} that is {age_days} days old!")
                    print(f"   Fix: Rotate this access key immediately")
                    findings.append({
                        "check": "Access Key Age",
                        "status": "FAIL",
                        "risk": "HIGH",
                        "detail": f"User {username} key {key_id} is {age_days} days old"
                    })
                elif age_days > 90 and status == 'Inactive':
                    print(f"⚠️  User '{username}' has an inactive old key")
                    print(f"   ({age_days} days old) — consider deleting it")
                    findings.append({
                        "check": "Access Key Age",
                        "status": "WARN",
                        "risk": "LOW",
                        "detail": f"User {username} has inactive key {age_days} days old"
                    })
                else:
                    print(f"✅ User '{username}' key is {age_days} days old — OK")
                    findings.append({
                        "check": "Access Key Age",
                        "status": "PASS",
                        "risk": "NONE",
                        "detail": f"User {username} key is {age_days} days old"
                    })

        print()
        return findings

    except Exception as e:
        print(f"⚠️  Could not check access keys: {e}\n")
        return []

# ============================================
# STEP 5: Check S3 buckets for public access
# ============================================
def check_s3_public_access(s3):
    print("=" * 55)
    print("CHECK 4: Public S3 Buckets")
    print("=" * 55)

    findings = []

    try:
        buckets = s3.list_buckets()['Buckets']

        if len(buckets) == 0:
            print("✅ No S3 buckets found in this account\n")
            findings.append({
                "check": "S3 Public Access",
                "status": "PASS",
                "risk": "NONE",
                "detail": "No S3 buckets exist in this account"
            })
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
                    print(f"✅ Bucket '{bucket_name}' — public access blocked")
                    findings.append({
                        "check": "S3 Public Access",
                        "status": "PASS",
                        "risk": "NONE",
                        "detail": f"Bucket {bucket_name} has public access blocked"
                    })
                else:
                    print(f"🔴 HIGH RISK: Bucket '{bucket_name}' may be publicly accessible!")
                    print(f"   Fix: Enable Block Public Access on this bucket")
                    findings.append({
                        "check": "S3 Public Access",
                        "status": "FAIL",
                        "risk": "HIGH",
                        "detail": f"Bucket {bucket_name} does not block all public access"
                    })

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                print(f"🔴 HIGH RISK: Bucket '{bucket_name}' has NO public")
                print(f"   access block configuration!")
                findings.append({
                    "check": "S3 Public Access",
                    "status": "FAIL",
                    "risk": "HIGH",
                    "detail": f"Bucket {bucket_name} has no public access block"
                })

            except Exception as e:
                print(f"⚠️  Could not check bucket '{bucket_name}': {e}")

        print()
        return findings

    except Exception as e:
        print(f"⚠️  Could not check S3 buckets: {e}\n")
        return []

# ============================================
# STEP 6: Show summary and save report
# ============================================
def show_summary_and_save(all_findings):
    high = [f for f in all_findings if f['risk'] == 'HIGH']
    medium = [f for f in all_findings if f['risk'] == 'MEDIUM']
    low = [f for f in all_findings if f['risk'] == 'LOW']
    passed = [f for f in all_findings if f['status'] == 'PASS']

    print("=" * 55)
    print("   SECURITY SUMMARY")
    print("=" * 55)
    print(f"Total checks performed: {len(all_findings)}")
    print(f"Passed:       {len(passed)}")
    print(f"High Risk:    {len(high)}")
    print(f"Medium Risk:  {len(medium)}")
    print(f"Low Risk:     {len(low)}")

    if high:
        print("\nIMMEDIATE ACTION REQUIRED:")
        for f in high:
            print(f"  - {f['detail']}")

    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cloud_security_report_{timestamp}.json"

    with open(filename, 'w') as f:
        json.dump({
            "scan_date": timestamp,
            "total_checks": len(all_findings),
            "findings": all_findings
        }, f, indent=4)

    print(f"\n📄 Report saved to: {filename}")
    print("\n" + "=" * 55)
    print("   SCAN COMPLETE")
    print("=" * 55 + "\n")

# ============================================
# MAIN: Run everything
# ============================================
def main():
    iam, s3 = connect_to_aws()

    if not iam:
        return

    all_findings = []
    all_findings += check_root_account(iam)
    all_findings += check_iam_mfa(iam)
    all_findings += check_old_access_keys(iam)
    all_findings += check_s3_public_access(s3)

    show_summary_and_save(all_findings)

main()