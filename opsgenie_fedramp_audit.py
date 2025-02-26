#!/usr/bin/env python3
"""
OpsGenie FedRAMP Compliance Audit Script

This script performs an automated audit of OpsGenie configuration and settings
to evaluate compliance with FedRAMP security requirements.

Requirements:
- Python 3.8+
- Requests library
- Python-dotenv (for secure API key management)
- Pandas (for reporting)
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta

import pandas as pd
import requests
from dotenv import load_dotenv

# Load API key from environment variable
load_dotenv()
API_KEY = os.getenv("OPSGENIE_API_KEY")

# FedRAMP control mappings to OpsGenie features
FEDRAMP_CONTROL_MAPPING = {
    "AC-2": ["User Management", "Access Control"],
    "AC-3": ["Authorization", "Role-Based Access Control"],
    "AC-6": ["Least Privilege", "Permission Sets"],
    "AC-7": ["Failed Login Attempts", "Account Lockout"],
    "AU-2": ["Auditable Events", "Audit Logs"],
    "AU-3": ["Audit Content", "Log Detail"],
    "AU-6": ["Audit Review", "Log Analysis"],
    "IA-2": ["Identification & Authentication", "MFA"],
    "IA-5": ["Authenticator Management", "Password Policy"],
    "CP-9": ["Backup", "Data Retention"],
    "SC-8": ["Data in Transit", "TLS/SSL"],
    "SC-13": ["Cryptography", "Encryption"],
}

# Base URL for OpsGenie API
BASE_URL = "https://api.opsgenie.com/v2"


def check_auth():
    """Verify API key works and has sufficient permissions"""
    headers = {
        "Authorization": f"GenieKey {API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{BASE_URL}/account", headers=headers)
        response.raise_for_status()
        print("✅ Authentication successful")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Authentication failed: {e}")
        return False


def audit_user_management():
    """Audit user management settings for AC-2, AC-3, AC-6"""
    headers = {
        "Authorization": f"GenieKey {API_KEY}",
        "Content-Type": "application/json"
    }
    
    findings = []
    
    # Get all users
    try:
        response = requests.get(f"{BASE_URL}/users", headers=headers)
        response.raise_for_status()
        users = response.json()["data"]
        
        # Check for inactive users
        inactive_users = [user for user in users if not user.get("blocked") and not user.get("verified")]
        if inactive_users:
            findings.append({
                "control": "AC-2",
                "status": "Non-Compliant",
                "finding": f"Found {len(inactive_users)} inactive user accounts that are not blocked",
                "recommendation": "Disable or remove inactive user accounts"
            })
        else:
            findings.append({
                "control": "AC-2",
                "status": "Compliant",
                "finding": "No inactive user accounts detected",
                "recommendation": "Continue regular user account reviews"
            })
        
        # Get all teams and roles
        response = requests.get(f"{BASE_URL}/teams", headers=headers)
        response.raise_for_status()
        teams = response.json()["data"]
        
        role_based_access = False
        for team in teams:
            if "role" in team or "permissions" in team:
                role_based_access = True
                break
        
        if role_based_access:
            findings.append({
                "control": "AC-3",
                "status": "Compliant",
                "finding": "Role-based access control is implemented",
                "recommendation": "Review role definitions for principle of least privilege"
            })
        else:
            findings.append({
                "control": "AC-3",
                "status": "Non-Compliant",
                "finding": "Role-based access control not fully implemented",
                "recommendation": "Implement role-based access control for all teams"
            })
            
    except requests.exceptions.RequestException as e:
        findings.append({
            "control": "AC-2, AC-3, AC-6",
            "status": "Error",
            "finding": f"Could not retrieve user management data: {e}",
            "recommendation": "Verify API permissions and retry"
        })
    
    return findings


def audit_authentication():
    """Audit authentication settings for IA-2, IA-5, AC-7"""
    headers = {
        "Authorization": f"GenieKey {API_KEY}",
        "Content-Type": "application/json"
    }
    
    findings = []
    
    try:
        # Check account-wide settings
        response = requests.get(f"{BASE_URL}/account", headers=headers)
        response.raise_for_status()
        account_settings = response.json()["data"]
        
        # Check for MFA
        if account_settings.get("userSettings", {}).get("mfaEnabled", False):
            findings.append({
                "control": "IA-2",
                "status": "Compliant",
                "finding": "Multi-factor authentication is enabled",
                "recommendation": "Continue enforcing MFA for all users"
            })
        else:
            findings.append({
                "control": "IA-2",
                "status": "Non-Compliant",
                "finding": "Multi-factor authentication is not enabled",
                "recommendation": "Enable and enforce MFA for all users"
            })
        
        # Check password policies
        pwd_policy = account_settings.get("userSettings", {}).get("passwordPolicy", {})
        if pwd_policy.get("minLength", 0) >= 12 and pwd_policy.get("mustContainUppercase", False) and pwd_policy.get("mustContainLowercase", False) and pwd_policy.get("mustContainNumber", False) and pwd_policy.get("mustContainSpecialChar", False):
            findings.append({
                "control": "IA-5",
                "status": "Compliant",
                "finding": "Password policy meets complexity requirements",
                "recommendation": "Continue enforcing strong password policies"
            })
        else:
            findings.append({
                "control": "IA-5",
                "status": "Non-Compliant",
                "finding": "Password policy does not meet complexity requirements",
                "recommendation": "Update password policy to require minimum 12 characters, uppercase, lowercase, numbers, and special characters"
            })
        
        # Check account lockout
        lockout = account_settings.get("userSettings", {}).get("accountLockout", {})
        if lockout.get("enabled", False) and lockout.get("maxAttempts", 0) <= 5:
            findings.append({
                "control": "AC-7",
                "status": "Compliant",
                "finding": "Account lockout policy is enforced",
                "recommendation": "Continue monitoring failed login attempts"
            })
        else:
            findings.append({
                "control": "AC-7",
                "status": "Non-Compliant",
                "finding": "Account lockout policy is not adequately configured",
                "recommendation": "Enable account lockout after 5 or fewer failed attempts"
            })
            
    except requests.exceptions.RequestException as e:
        findings.append({
            "control": "IA-2, IA-5, AC-7",
            "status": "Error",
            "finding": f"Could not retrieve authentication settings: {e}",
            "recommendation": "Verify API permissions and retry"
        })
    
    return findings


def audit_logging():
    """Audit logging settings for AU-2, AU-3, AU-6"""
    headers = {
        "Authorization": f"GenieKey {API_KEY}",
        "Content-Type": "application/json"
    }
    
    findings = []
    
    try:
        # Check audit log settings
        response = requests.get(f"{BASE_URL}/account/logging", headers=headers)
        response.raise_for_status()
        logging_settings = response.json()["data"]
        
        # Check if comprehensive logging is enabled
        if logging_settings.get("enabled", False):
            findings.append({
                "control": "AU-2",
                "status": "Compliant",
                "finding": "Audit logging is enabled",
                "recommendation": "Continue monitoring audit logs regularly"
            })
        else:
            findings.append({
                "control": "AU-2",
                "status": "Non-Compliant",
                "finding": "Audit logging is not enabled",
                "recommendation": "Enable comprehensive audit logging"
            })
        
        # Check log retention
        if logging_settings.get("retentionPeriod", 0) >= 90:
            findings.append({
                "control": "AU-3, AU-6",
                "status": "Compliant",
                "finding": f"Log retention period meets minimum requirement ({logging_settings.get('retentionPeriod')} days)",
                "recommendation": "Continue monitoring log retention policies"
            })
        else:
            findings.append({
                "control": "AU-3, AU-6",
                "status": "Non-Compliant",
                "finding": f"Log retention period does not meet minimum requirement (currently {logging_settings.get('retentionPeriod', 0)} days)",
                "recommendation": "Increase log retention period to at least 90 days"
            })
        
        # Check if log export is configured
        if logging_settings.get("exportEnabled", False):
            findings.append({
                "control": "AU-6",
                "status": "Compliant",
                "finding": "Log export is configured for centralized monitoring",
                "recommendation": "Verify logs are being properly analyzed in central system"
            })
        else:
            findings.append({
                "control": "AU-6",
                "status": "Non-Compliant",
                "finding": "Log export is not configured",
                "recommendation": "Configure log export to a centralized monitoring system"
            })
            
    except requests.exceptions.RequestException as e:
        findings.append({
            "control": "AU-2, AU-3, AU-6",
            "status": "Error",
            "finding": f"Could not retrieve logging settings: {e}",
            "recommendation": "Verify API permissions and retry"
        })
    
    return findings


def audit_encryption():
    """Audit encryption settings for SC-8, SC-13, CP-9"""
    headers = {
        "Authorization": f"GenieKey {API_KEY}",
        "Content-Type": "application/json"
    }
    
    findings = []
    
    try:
        # Check account security settings
        response = requests.get(f"{BASE_URL}/account/security", headers=headers)
        response.raise_for_status()
        security_settings = response.json()["data"]
        
        # Check data encryption
        if security_settings.get("dataEncryption", {}).get("enabled", False):
            findings.append({
                "control": "SC-13",
                "status": "Compliant",
                "finding": "Data encryption is enabled",
                "recommendation": "Verify encryption algorithms meet FIPS 140-2 requirements"
            })
        else:
            findings.append({
                "control": "SC-13",
                "status": "Non-Compliant",
                "finding": "Data encryption is not enabled or not configured properly",
                "recommendation": "Enable data encryption with FIPS 140-2 compliant algorithms"
            })
        
        # Check TLS settings
        if security_settings.get("tlsConfig", {}).get("minVersion", "") in ["TLS1.2", "TLS1.3"]:
            findings.append({
                "control": "SC-8",
                "status": "Compliant",
                "finding": f"TLS configuration meets minimum requirements (version {security_settings.get('tlsConfig', {}).get('minVersion')})",
                "recommendation": "Continue monitoring TLS configuration"
            })
        else:
            findings.append({
                "control": "SC-8",
                "status": "Non-Compliant",
                "finding": f"TLS configuration does not meet minimum requirements (version {security_settings.get('tlsConfig', {}).get('minVersion', 'not set')})",
                "recommendation": "Configure TLS to require minimum version 1.2"
            })
        
        # Check backup configuration
        response = requests.get(f"{BASE_URL}/account/backup", headers=headers)
        response.raise_for_status()
        backup_settings = response.json()["data"]
        
        if backup_settings.get("enabled", False) and backup_settings.get("frequency", "") in ["daily", "hourly"]:
            findings.append({
                "control": "CP-9",
                "status": "Compliant",
                "finding": f"Backup configuration is appropriately configured ({backup_settings.get('frequency')} backups)",
                "recommendation": "Verify backup restoration procedures are tested regularly"
            })
        else:
            findings.append({
                "control": "CP-9",
                "status": "Non-Compliant",
                "finding": "Backup configuration is not optimally configured",
                "recommendation": "Configure at least daily backups and test restoration procedures"
            })
            
    except requests.exceptions.RequestException as e:
        findings.append({
            "control": "SC-8, SC-13, CP-9",
            "status": "Error",
            "finding": f"Could not retrieve encryption and backup settings: {e}",
            "recommendation": "Verify API permissions and retry"
        })
    
    return findings


def generate_report(findings):
    """Generate a compliance report from findings"""
    # Create DataFrame
    df = pd.DataFrame(findings)
    
    # Count compliance status by control
    status_counts = df.groupby(['control', 'status']).size().unstack(fill_value=0)
    
    # Get overall compliance percentage
    total_controls = len(df)
    compliant_controls = len(df[df['status'] == 'Compliant'])
    compliance_percentage = (compliant_controls / total_controls) * 100 if total_controls > 0 else 0
    
    # Print summary
    print("\n" + "=" * 80)
    print(f"OpsGenie FedRAMP Compliance Audit Report - {datetime.now().strftime('%Y-%m-%d')}")
    print("=" * 80)
    print(f"\nOverall Compliance: {compliance_percentage:.2f}% ({compliant_controls}/{total_controls} controls)\n")
    
    # Print status by control category
    if not status_counts.empty:
        print("Compliance by Control Category:")
        print("-" * 40)
        print(status_counts)
        print()
    
    # Print detailed findings
    print("Detailed Findings:")
    print("-" * 80)
    for i, finding in enumerate(findings, 1):
        print(f"{i}. Control: {finding['control']} - {finding['status']}")
        print(f"   Finding: {finding['finding']}")
        print(f"   Recommendation: {finding['recommendation']}")
        print()
    
    # Export to Excel
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"opsgenie_fedramp_audit_{timestamp}.xlsx"
    
    with pd.ExcelWriter(filename, engine='openpyxl') as writer:
        # Summary sheet
        summary_data = {
            'Metric': ['Total Controls', 'Compliant', 'Non-Compliant', 'Error', 'Compliance Percentage'],
            'Value': [
                total_controls,
                df['status'].value_counts().get('Compliant', 0),
                df['status'].value_counts().get('Non-Compliant', 0),
                df['status'].value_counts().get('Error', 0),
                f"{compliance_percentage:.2f}%"
            ]
        }
        pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
        
        # Detailed findings
        df.to_excel(writer, sheet_name='Detailed Findings', index=False)
        
        # Recommendations sheet
        recommendations = df[df['status'] != 'Compliant'][['control', 'finding', 'recommendation']]
        if not recommendations.empty:
            recommendations.to_excel(writer, sheet_name='Recommendations', index=False)
    
    print(f"Report exported to {filename}")
    
    return filename


def main():
    parser = argparse.ArgumentParser(description='Audit OpsGenie for FedRAMP compliance')
    parser.add_argument('--api-key', help='OpsGenie API key (overrides environment variable)')
    args = parser.parse_args()
    
    # Use command line API key if provided
    global API_KEY
    if args.api_key:
        API_KEY = args.api_key
    
    if not API_KEY:
        print("Error: No API key provided. Set OPSGENIE_API_KEY environment variable or use --api-key")
        sys.exit(1)
    
    # Verify authentication
    if not check_auth():
        sys.exit(1)
    
    print("\nRunning FedRAMP compliance audit...")
    
    # Collect findings from all audit modules
    findings = []
    findings.extend(audit_user_management())
    findings.extend(audit_authentication())
    findings.extend(audit_logging())
    findings.extend(audit_encryption())
    
    # Generate and export report
    report_file = generate_report(findings)
    
    print("\nFedRAMP compliance audit complete!")
    print(f"Detailed report available in: {report_file}")


if __name__ == "__main__":
    main()