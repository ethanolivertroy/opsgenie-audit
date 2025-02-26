# Opsgenie Audit

This Python script will audit your OpsGenie instance for FedRAMP compliance by checking various security controls and configurations. Here's what the script does:

1. **Authentication Checks**: Verifies MFA implementation, password policies, and account lockout settings
2. **User Management**: Audits for inactive accounts, role-based access controls, and least privilege principles
3. **Logging & Auditing**: Checks if comprehensive logging is enabled with appropriate retention periods
4. **Encryption**: Verifies data encryption, TLS configuration, and backup procedures

### How to Use the Script:

1. Install the required Python libraries:
   ```
   pip install requests python-dotenv pandas openpyxl
   ```

2. Set your OpsGenie API key as an environment variable:
   ```
   export OPSGENIE_API_KEY="your-api-key-here"
   ```

3. Run the script:
   ```
   python opsgenie_fedramp_audit.py
   ```

The script will generate a comprehensive report in both console output and Excel format, showing your compliance status for each control and providing recommendations for any non-compliant areas.

> Note that you'll need appropriate API permissions in OpsGenie to run all checks successfully.