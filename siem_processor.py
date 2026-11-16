import os
import json
import base64
import gzip
import boto3

dynamodb = boto3.resource("dynamodb")
METRICS_TABLE_NAME = os.environ.get("METRICS_TABLE", "SiemMetricsTable")
metrics_table = dynamodb.Table(METRICS_TABLE_NAME)

def lambda_handler(event, context):
    # CloudWatch log events arrive compressed and base64 encoded
    compressed_payload = base64.b64decode(event['awslogs']['data'])
    uncompressed_data = gzip.decompress(compressed_payload)
    log_data = json.loads(uncompressed_data)

    recon_indicators = ["curl", "python-requests", "nikto", "sqlmap", "gobuster", "nmap", "masscan"]

    for log_event in log_data.get("logEvents", []):
        message = log_event.get("message", "")
        try:
            if "cloud-resume-visitor-counter" in message:
                data = json.loads(message)
                user_agent = data.get("UserAgent", "").lower()
                ip_hash = data.get("IpHash", "unknown")
                timestamp = data.get("Timestamp", "0")
                
                is_suspicious = any(scanner in user_agent for scanner in recon_indicators)
                metric_id = f"VISIT#{ip_hash}#{timestamp}"

                # Write security metrics into your SiemMetricsTable
                metrics_table.put_item(
                    Item={
                        "id": metric_id,
                        "IpHash": ip_hash,
                        "UserAgent": user_agent,
                        "Path": data.get("Path", "/"),
                        "Method": data.get("Method", "GET"),
                        "IsSuspicious": is_suspicious,
                        "Timestamp": timestamp
                    }
                )

                if is_suspicious:
                    print(f"SIEM ALERT: Reconnaissance tool detected: {user_agent} from IP hash {ip_hash}")
                else:
                    print(f"SIEM INGEST: Processed log telemetry for IP hash {ip_hash}")
        except Exception as e:
            print(f"SIEM Error processing log event: {str(e)}")

    return {"statusCode": 200, "body": "Logs processed successfully"}
