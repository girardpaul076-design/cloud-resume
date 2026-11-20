## Operations & Testing Playbook

* **Region:** `us-east-2`
* **Stack:** `security-monitor-v3`
* **Live SIEM Dashboard:** https://main.d3fza2e9ubh05j.amplifyapp.com/
* **API Base URL:** https://amf2gdtvnk.execute-api.us-east-2.amazonaws.com
* **SIEM Telemetry Endpoint:** https://amf2gdtvnk.execute-api.us-east-2.amazonaws.com/siem?view=siem
* **Victim Bucket:** `siem-simulation-victim-740868193033-us-east-2`

### 1. Verify Local AWS Session
Run from the repository root in PowerShell with `.venv` active:

```powershell
python -c "import boto3; print(boto3.client('sts').get_caller_identity()['Arn'])"
