# 보안 점검 항목: API Server 권한 제어
# scanner/checks/api_server_authorization.py
from .base import Check
import subprocess, json

class APIServerAuthorizationCheck(Check):
    id = "CHK-M-API-004"
    name = "API Server authorization mode (AlwaysAllow) 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _authorization_modes_from_args(self, args_list):
        """
        args_list: 리스트 형태의 command/args
        반환: list of modes (소문자)
        """
        for i, a in enumerate(args_list):
            if a.startswith("--authorization-mode="):
                val = a.split("=", 1)[1]
                return [m.strip().lower() for m in val.split(",") if m.strip()]
            if a == "--authorization-mode":
                if i + 1 < len(args_list):
                    val = args_list[i+1]
                    return [m.strip().lower() for m in val.split(",") if m.strip()]
        return []

    def run(self, kubeconfig=''):
        # kube-system에서 kube-apiserver 파드 찾기
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
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 수 있음 또는 권한 부족)",
                "Evidence": {"pod_count": len(pods.get("items", []))},
                "Remediation": "컨트롤플레인 노드 또는 클라우드 제공자 문서에서 authorization-mode 설정 확인"
            }]

        findings = []
        for p in apiserver_pods:
            meta = p.get("metadata", {})
            name = meta.get("name")
            spec = p.get("spec", {}) or {}
            containers = spec.get("containers", []) or []

            args_list = []
            for c in containers:
                if c.get("command"):
                    args_list += c.get("command")
                if c.get("args"):
                    args_list += c.get("args")

            modes = self._authorization_modes_from_args(args_list)
            # modes가 비어있으면 kube-apiserver 기본값(AlwaysAllow 가능) 확인 권고
            if not modes:
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": "--authorization-mode 플래그 없음(기본값에 따라 AlwaysAllow 일 수 있음). 명시적으로 RBAC 사용 권장",
                    "Evidence": {"args": args_list},
                    "Remediation": "매니페스트에 --authorization-mode=RBAC (또는 Node,RBAC 등)을 명시적으로 설정"
                })
                continue

            # AlwaysAllow 포함 여부 검사
            if any(m == "alwaysallow" for m in modes):
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": f"--authorization-mode contains AlwaysAllow: {modes}",
                    "Evidence": {"authorization_modes": modes, "args": args_list},
                    "Remediation": "매니페스트에서 AlwaysAllow 제거하고 RBAC 사용 (예: --authorization-mode=Node,RBAC 또는 --authorization-mode=RBAC)"
                })
            else:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": f"--authorization-mode 설정이 적절함: {modes}",
                    "Evidence": {"authorization_modes": modes, "args": args_list},
                    "Remediation": ""
                })

        return findings
