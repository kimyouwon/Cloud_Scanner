import subprocess
import json

def check_privileged_containers():
    result = subprocess.run(
        ["kubectl", "get", "pods", "-A", "-o", "json"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0 or not result.stdout:
        print("❌ kubectl 명령 실패 (privileged 검사)")
        print("stderr:", result.stderr)
        return []

    try:
        pods = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("❌ JSON 파싱 실패 (privileged 검사)")
        return []

    findings = []

    for pod in pods['items']:
        for container in pod['spec'].get('containers', []):
            security_ctx = container.get('securityContext', {})
            if security_ctx.get('privileged') is True:
                findings.append({
                    "namespace": pod['metadata']['namespace'],
                    "pod": pod['metadata']['name'],
                    "container": container['name'],
                    "reason": "privileged 컨테이너 사용 중"
                })

    return findings
