import subprocess
import json

def check_host_network():
    result = subprocess.run(
        ["kubectl", "get", "pods", "-A", "-o", "json"],
        capture_output=True,
        text=True
    )
    
# Debug
    print("STDOUT:", result.stdout[:200])
    print("STDERR:", result.stderr)

    if result.returncode != 0:
        print("❌ kubectl 명령 실패. 클러스터가 켜져 있는지 확인하세요.")
        return []

    try:
        pods = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("❌ JSON 파싱 실패. 출력 내용 확인 필요.")
        return []

    findings = []

    for pod in pods.get('items', []):
        if pod['spec'].get('hostNetwork'):
            findings.append({
                "namespace": pod['metadata']['namespace'],
                "pod": pod['metadata']['name'],
                "reason": "hostNetwork 사용 중"
            })

    return findings