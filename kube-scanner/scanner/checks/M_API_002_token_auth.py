# 보안 점검 항목: API Server 취약한 방식의 인증 사용 제한
# scanner/checks/api_server_token_auth.py
from .base import Check
import subprocess, json

class APIServerTokenAuthCheck(Check):
    id = "CHK-M-API-002"
    name = "API Server --token-auth-file (정적 토큰) 사용 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 5
    risk_level = 9
    description = "API server에서 취약한 방식의 인증을 사용할 경우, 비인가자의 접근으로 인해 Kubernetes 시스템의 모든 요소에 영향을 줄 수 있다."
    recommended_setting = "API server 취약한 방식의 인증 사용을 제한한 경우\n- --token-auth-file 플래그 제거 (정적 토큰 파일 사용 금지)"
    verification_command = "kubectl get pods -n kube-system -o json | jq '.items[] | select(.metadata.name | contains(\"kube-apiserver\")) | .spec.containers[].args' | grep -i token-auth-file"

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def run(self, kubeconfig=''):
        # 1) kube-system에서 apiserver 관련 파드 수집
        res = self._kubectl(["get", "pods", "-n", "kube-system", "-o", "json"], kubeconfig)
        if res.returncode != 0:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "kubectl 실행 실패: " + (res.stderr or res.stdout).strip(),
                "Evidence": {},
                "Remediation": "kubectl 접근 권한(특히 kube-system 조회) 확인"
            }]

        try:
            pods = json.loads(res.stdout)
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": f"JSON 파싱 실패: {e}",
                "Evidence": {},
                "Remediation": "kubectl 출력 확인"
            }]

        apiserver_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-apiserver" in name:
                apiserver_pods.append(it)

        if not apiserver_pods:
            # 관리형 컨트롤플레인인지 또는 권한 부족
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 가능성 또는 권한 부족)",
                "Evidence": {"pod_count": len(pods.get("items", []))},
                "Remediation": "관리형 클러스터인지 확인하고, 컨트롤플레인 접근 권한이 있다면 노드의 kube-apiserver 매니페스트를 점검"
            }]

        findings = []
        for p in apiserver_pods:
            meta = p.get("metadata", {})
            name = meta.get("name")
            spec = p.get("spec", {}) or {}
            containers = spec.get("containers", []) or []

            # args/command 합치기
            args_list = []
            for c in containers:
                if c.get("command"):
                    args_list += c.get("command")
                if c.get("args"):
                    args_list += c.get("args")
            args_str = " ".join(args_list)

            # 토큰 파일 검사: --token-auth-file=path 또는 --token-auth-file path 형태
            token_flag_present = any(('--token-auth-file=' in a) for a in args_list) or ('--token-auth-file' in args_list)

            if token_flag_present:
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": "--token-auth-file 플래그가 설정되어 정적 토큰 파일 사용 중",
                    "Evidence": {"args": args_list},
                    "Remediation": "정적 토큰 사용을 중단하세요. 대신 인증서/OIDC/서비스어카운트 등 현대적 인증 방식을 사용하고, kube-apiserver 매니페스트에서 --token-auth-file 플래그 제거",
                })
            else:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": "--token-auth-file 플래그 미발견(정적 토큰 사용 안함)",
                    "Evidence": {"args": args_list},
                    "Remediation": ""
                })
        return findings
