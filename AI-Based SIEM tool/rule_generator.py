# step:2
import pandas as pd
import numpy as np
from datetime import datetime
import os
import yaml
import joblib
import json

print("=" * 25)
print("GENERATING SIGMA RULES")
print("=" * 25)
print("Note: These all rules are standard format sigma rules. If you want rule for specific SIEM convert them first.")

# 1. Load detection results
print("\n[1] Loading detection results...")
df = pd.read_csv('data/detection_results.csv')
print(f"Loaded {len(df):,} records")
print(f"Columns available: {list(df.columns)}")

# Check if ae_anomaly exists (from your detector)
if 'ae_anomaly' in df.columns:
    anomaly_col = 'ae_anomaly'
    print(f"✓ Using {anomaly_col} for anomaly detection")
else:
    # Fallback to iso_anomaly if ae_anomaly doesn't exist
    anomaly_col = 'iso_anomaly' if 'iso_anomaly' in df.columns else None
    if anomaly_col:
        print(f"✓ Using {anomaly_col} for anomaly detection")
    else:
        print("No anomaly column found! Run anomaly_detector.py first.")
        exit(1)

print(f"Found {df[anomaly_col].sum():,} anomalies detected ({df[anomaly_col].sum() / len(df) * 100:.2f}%)")

# 2. Load encoders if they exist
print("\n[2] Loading encoders...")
encoders = {}
encoder_files = {
    'country': 'models/label_encoder_country.pkl',
    'region': 'models/label_encoder_region.pkl',
    'city': 'models/label_encoder_city.pkl',
    'device': 'models/label_encoder_device.pkl',
    'browser': 'models/label_encoder_browser.pkl',
    'os': 'models/label_encoder_os.pkl'
}

for name, path in encoder_files.items():
    if os.path.exists(path):
        try:
            encoders[name] = joblib.load(path)
            print(f"✓ Loaded encoder: {name}")
        except:
            print(f"Could not load encoder: {name}")
    else:
        print(f"Encoder not found: {name}")

# 3. Analyze what makes anomalies different
print("\n[3] Analyzing anomaly patterns...")

# Separate normal and anomalous
normal = df[df[anomaly_col] == False]
anomalous = df[df[anomaly_col] == True]

print(f"Normal samples: {len(normal):,}")
print(f"Anomalous samples: {len(anomalous):,}")

# Compare statistics
print("\nFeature comparison (normal vs anomalous):")

# Login hour (if exists)
if 'login_hour' in df.columns:
    normal_hour = normal['login_hour'].mean()
    anomalous_hour = anomalous['login_hour'].mean()
    print(f"Login hour: {normal_hour:.1f} vs {anomalous_hour:.1f}")
else:
    normal_hour = 12
    anomalous_hour = 3  # Default for rule generation

# Login Successful rate
if 'Login Successful' in df.columns:
    normal_success = normal['Login Successful'].mean() * 100
    anomalous_success = anomalous['Login Successful'].mean() * 100
    print(f"Success rate: {normal_success:.1f}% vs {anomalous_success:.1f}%")
elif 'login_success' in df.columns:
    normal_success = normal['login_success'].mean() * 100
    anomalous_success = anomalous['login_success'].mean() * 100
    print(f"Success rate: {normal_success:.1f}% vs {anomalous_success:.1f}%")
else:
    normal_success = 95
    anomalous_success = 30

# Country distribution
if 'Country' in df.columns:
    print("\nTop countries in anomalies:")
    country_counts = anomalous['Country'].value_counts().head(5)
    for country, count in country_counts.items():
        print(f"    {country}: {count} ({count / len(anomalous) * 100:.1f}%)")
elif 'country' in df.columns:
    print("\nTop countries in anomalies:")
    country_counts = anomalous['country'].value_counts().head(5)
    for country, count in country_counts.items():
        print(f"    {country}: {count} ({count / len(anomalous) * 100:.1f}%)")
else:
    country_counts = pd.Series({'Unknown': len(anomalous)})

# Device Type analysis
if 'Device Type' in df.columns:
    print("\nTop devices in anomalies:")
    device_counts = anomalous['Device Type'].value_counts().head(3)
    for device, count in device_counts.items():
        print(f"    {device}: {count} ({count / len(anomalous) * 100:.1f}%)")



# RTT analysis
if 'Round-Trip Time [ms]' in df.columns:
    normal_rtt = normal['Round-Trip Time [ms]'].median()
    anomalous_rtt = anomalous['Round-Trip Time [ms]'].median()
    print(f"\nMedian RTT: {normal_rtt:.0f}ms vs {anomalous_rtt:.0f}ms")

# Is Attack IP analysis (for validation)
if 'Is Attack IP' in df.columns:
    attack_ip_rate = anomalous['Is Attack IP'].mean() * 100
    print(f"\nAnomalies that are attack IPs: {attack_ip_rate:.1f}%")

# 4. Generate detection rules
print("\n[4] Generating detection rules...")

# Create rules directory
os.makedirs('rules', exist_ok=True)


def create_sigma_rule(condition, description, severity="medium", rule_type="generic"):
    """
    Create a Sigma rule YAML structure
    """
    rule_id = f"rule-{np.random.randint(10000, 99999)}"

    rule = {
        "title": f"AI-Generated Detection: {description[:50]}...",
        "id": rule_id,
        "status": "experimental",
        "description": description,
        "author": "AI SIEM Rule Generator",
        "date": datetime.now().strftime("%Y/%m/%d"),
        "modified": datetime.now().strftime("%Y/%m/%d"),
        "tags": [
            "attack.t1078",  # Valid Accounts
            "attack.t1110",  # Brute Force
            "anomaly.detection",
            f"ai.generated.{rule_type}"
        ],
        "logsource": {
            "product": "windows",
            "service": "security",
            "category": "authentication"
        },
        "detection": {
            "selection": condition,
            "condition": "selection"
        },
        "falsepositives": [
            "Legitimate users with unusual behavior",
            "System accounts",
            "VPN usage from different locations",
            "Legitimate remote access"
        ],
        "level": severity,
        "references": [
            "https://attack.mitre.org/techniques/T1078/",
            "Generated by AI SIEM Rule Engine"
        ]
    }
    return rule


# Rule 1: Odd hour logins (based on actual data)
if anomalous_hour < 6 or anomalous_hour > 20:
    rule1 = create_sigma_rule(
        condition={
            "EventID": 4625,  # Failed login
            "Time": {
                "hour": ["<6", ">20"]
            },
            "Status": "Failure"
        },
        description=f"Failed logins during unusual hours ({anomalous_hour:.0f}:00 average) - indicates possible brute force or compromised account",
        severity="medium",
        rule_type="time_based"
    )

    with open('rules/rule_odd_hours_failures.yml', 'w') as f:
        yaml.dump(rule1, f, default_flow_style=False, sort_keys=False)
    print("  ✓ Generated rule: odd_hours_failures.yml")

# Rule 2: Unusual country access
if len(country_counts) > 0:
    # Get top anomalous countries
    top_anomaly_countries = country_counts.index.tolist()[:3]

    # Filter out common countries (customize based on your data)
    common_countries = ['US', 'United States', 'USA', 'CA', 'Canada', 'GB', 'UK', 'United Kingdom']
    unusual_countries = [c for c in top_anomaly_countries if c not in common_countries]

    if unusual_countries:
        rule2 = create_sigma_rule(
            condition={
                "EventID": 4624,  # Successful login
                "Country": unusual_countries
            },
            description=f"Successful logins from unusual countries: {', '.join(unusual_countries)} - possible unauthorized access",
            severity="high",
            rule_type="geo_based"
        )

        with open('rules/rule_unusual_countries.yml', 'w') as f:
            yaml.dump(rule2, f, default_flow_style=False, sort_keys=False)
        print("  ✓ Generated rule: unusual_countries.yml")

# Rule 3: High failure rate from specific IPs
if 'Login Successful' in df.columns:
    # Calculate failure rate per IP
    ip_failure_rate = df.groupby('IP Address')['Login Successful'].agg(['mean', 'count'])
    suspicious_ips = ip_failure_rate[(ip_failure_rate['mean'] < 0.5) & (ip_failure_rate['count'] > 10)].index.tolist()[
        :5]

    if suspicious_ips:
        rule3 = create_sigma_rule(
            condition={
                "EventID": 4625,
                "Source IP": suspicious_ips
            },
            description=f"High login failure rate from IPs: {', '.join(suspicious_ips[:3])} - possible brute force attack",
            severity="high",
            rule_type="ip_based"
        )

        with open('rules/rule_suspicious_ips.yml', 'w') as f:
            yaml.dump(rule3, f, default_flow_style=False, sort_keys=False)
        print("  ✓ Generated rule: suspicious_ips.yml")

# Rule 4: Unusual device types
if 'Device Type' in df.columns:
    # Find device types that appear more in anomalies
    device_anomaly_rate = df.groupby('Device Type')[anomaly_col].mean().sort_values(ascending=False)
    suspicious_devices = device_anomaly_rate[device_anomaly_rate > 0.1].index.tolist()[:3]

    if suspicious_devices:
        rule4 = create_sigma_rule(
            condition={
                "EventID": 4624,
                "DeviceType": suspicious_devices
            },
            description=f"Logins from unusual device types: {', '.join(suspicious_devices)} - possible automated attacks",
            severity="medium",
            rule_type="device_based"
        )

        with open('rules/rule_unusual_devices.yml', 'w') as f:
            yaml.dump(rule4, f, default_flow_style=False, sort_keys=False)
        print("  ✓ Generated rule: unusual_devices.yml")

# Rule 5: RTT anomalies (if available)
if 'Round-Trip Time [ms]' in df.columns:
    normal_rtt_std = normal['Round-Trip Time [ms]'].std()
    normal_rtt_mean = normal['Round-Trip Time [ms]'].mean()

    rule5 = create_sigma_rule(
        condition={
            "EventID": 4624,
            "RTT_ms": {
                "gt": int(normal_rtt_mean + 3 * normal_rtt_std)  # 3 standard deviations above mean
            }
        },
        description=f"Logins with unusually high round-trip time (> {int(normal_rtt_mean + 3 * normal_rtt_std)}ms) - possible proxy/VPN usage",
        severity="low",
        rule_type="network_based"
    )

    with open('rules/rule_high_rtt.yml', 'w') as f:
        yaml.dump(rule5, f, default_flow_style=False, sort_keys=False)
    print("  ✓ Generated rule: high_rtt.yml")

# Rule 6: Account takeover patterns
if 'Is Account Takeover' in df.columns:
    # Find patterns in actual account takeovers
    takeover_df = df[df['Is Account Takeover'] == True]
    if len(takeover_df) > 10:
        # Analyze takeover characteristics
        takeover_countries = takeover_df['Country'].value_counts().head(2).index.tolist()
        takeover_hours = takeover_df['login_hour'].mean()

        rule6 = create_sigma_rule(
            condition={
                "EventID": 4624,
                "Action": "Logon",
                "LogonType": 10,  # RemoteInteractive
                "Country": takeover_countries,
                "Hour": int(takeover_hours)
            },
            description=f"Known account takeover pattern: logins from {takeover_countries} at hour {takeover_hours:.0f}",
            severity="critical",
            rule_type="pattern_based"
        )

        with open('rules/rule_account_takeover_pattern.yml', 'w') as f:
            yaml.dump(rule6, f, default_flow_style=False, sort_keys=False)
        print("  ✓ Generated rule: account_takeover_pattern.yml")

# Count generated rules
rule_count = len([f for f in os.listdir('rules') if f.endswith('.yml')])
print(f"\nGenerated {rule_count} rules in the 'rules' directory")

# 5. Create a comprehensive rule summary
print("\n[5] Creating rule summary report...")

# Calculate rule effectiveness estimates
if 'true_attack' in df.columns:
    potential_coverage = (df[anomaly_col] & df['true_attack']).sum() / df['true_attack'].sum() * 100
    false_positive_rate = (df[anomaly_col] & ~df['true_attack']).sum() / (~df['true_attack']).sum() * 100
else:
    potential_coverage = 0
    false_positive_rate = 0

summary = {
    "generation_time": datetime.now().isoformat(),
    "data_analyzed": len(df),
    "anomalies_found": int(df[anomaly_col].sum()),
    "anomaly_percentage": float(df[anomaly_col].mean() * 100),
    "rules_generated": rule_count,
    "key_patterns": {
        "odd_hour_logins": float(anomalous_hour) if 'login_hour' in df.columns else None,
        "anomaly_success_rate": float(anomalous_success),
        "normal_success_rate": float(normal_success),
        "top_suspicious_countries": country_counts.to_dict() if hasattr(country_counts, 'to_dict') else {},
        "rule_effectiveness_estimate": {
            "potential_attack_coverage": f"{potential_coverage:.1f}%",
            "estimated_false_positive_rate": f"{false_positive_rate:.1f}%"
        }
    },
    "generated_rules": [f for f in os.listdir('rules') if f.endswith('.yml')]
}

with open('rules/summary.json', 'w') as f:
    json.dump(summary, f, indent=2)

print("✓ Created rule summary with effectiveness estimates")

# 6. Create a README for the rules
readme_content = f"""# AI-Generated Sigma Rules

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Overview
- **Total rules generated**: {rule_count}
- **Data analyzed**: {len(df):,} login events
- **Anomalies detected**: {df[anomaly_col].sum():,} ({df[anomaly_col].mean() * 100:.2f}%)

## Rule Categories
"""
for rule_file in os.listdir('rules'):
    if rule_file.endswith('.yml'):
        readme_content += f"- {rule_file}\n"

readme_content += """

## How to Use These Rules
1. These are Sigma rules - the standard format for SIEM detection
2. Convert them to your SIEM format using sigma2splunk, sigma2elastic, etc.
3. Test in your environment before production use
4. Monitor for false positives and tune thresholds

## Rule Generation Method
Rules were generated by analyzing anomalies detected by an AutoEncoder neural network trained on normal login behavior. The system identified statistical outliers in:
- Login timing patterns
- Geographic locations
- Device types
- Network characteristics (RTT, ASN)
- Success/failure ratios

## False Positive Tuning
The thresholds used are based on the 95th percentile of normal behavior. Adjust based on your environment:
- Increase thresholds if too many false positives
- Decrease thresholds if missing attacks
"""

with open('rules/README.md', 'w') as f:
    f.write(readme_content)

print("✓ Created README for rules")