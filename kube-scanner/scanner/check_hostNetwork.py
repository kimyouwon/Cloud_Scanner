import subprocess
import json

def check_host_network():
    result = subprocess.run(
        ["kubectl", "get", "pods", "-A", "-o", "json"],
        capture_output=True,
        text=True
    )
    pods = json.loads(result.stdout)
    findings = []

    for pod in pods['items']:
        if pod['spec'].get('hostNetwork'):
            findings.append({
                "namespace": pod['metadata']['namespace'],
                "pod": pod['metadata']['name'],
                "reason": "hostNetwork 사용 중"
            })

    return findings
