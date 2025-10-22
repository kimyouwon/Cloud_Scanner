# scanner/checks/api_server_auth.py
from .base import Check
import subprocess, json, shlex

class APIServerAuthCheck(Check):
    id = "CHK-API-001"
    name = "API Server 익명(anonymous) 접근 및 ServiceAccount lookup 검사"
    category = "ControlPlane"
    severity = "Critical"

    def _kubectl_json(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res

    def run(self, kubeconfig=''):
        # 1) kube-system에서 kube-apiserver 파드 찾기
        res = self._kubectl_json(["get", "pods", "-n", "kube-system", "-o", "json"], kubeconfig)
        if res.returncode != 0:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "kubectl 명령 실패: " + (res.stderr or res.stdout).strip(),
                "Evidence": {},
                "Remediation": "kubectl 접근 및 권한(특히 kube-system 조회) 확인"
            }]
        try:
            pods = json.loads(res.stdout)
        except Exception as e:
            return [{
                "CheckID": self.id, "Result":"ERROR",
                "Reason": f"JSON 파싱 실패: {e}",
                "Evidence": {},
                "Remediation": "kubectl 출력 확인"
            }]

        # kube-apiserver라는 이름을 포함하는 파드를 찾음
        apiserver_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-apiserver" in name:
                apiserver_pods.append(it)

        if not apiserver_pods:
            # Managed control plane 또는 접근 권한 부족 가능
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에 kube-apiserver 파드를 찾지 못함 (관리형 컨트롤 플레인일 수 있음 또는 권한 부족)",
                "Evidence": {"pod_count": len(pods.get("items", []))},
                "Remediation": "컨트롤플레인 노드에서 /etc/kubernetes/manifests/kube-apiserver.yaml 또는 클라우드 제공자 문서 확인. (관리형 클러스터이면 제어판 플래그를 수정할 수 없음)"
            }]

        findings = []
        # 각 apiserver 파드의 컨테이너 args 확인
        for p in apiserver_pods:
            meta = p.get("metadata", {})
            name = meta.get("name")
            spec = p.get("spec", {})
            containers = spec.get("containers", []) or []
            # 보통 첫 컨테이너가 kube-apiserver
            args_list = []
            for c in containers:
                # args 또는 command 둘 다 체크
                if c.get("args"):
                    args_list += c.get("args")
                if c.get("command"):
                    args_list += c.get("command")
            args_str = " ".join(args_list)

            anon_ok = "--anonymous-auth=false" in args_str
            sa_lookup_ok = "--service-account-lookup=true" in args_str or "--service-account-lookup" in args_str and "--service-account-lookup=false" not in args_str

            if anon_ok and sa_lookup_ok:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": "kube-apiserver에 anonymous-auth=false 및 service-account-lookup=true 설정이 확인됨",
                    "Evidence": {"args": args_list},
                    "Remediation": ""
                })
            else:
                reason_parts = []
                if not anon_ok:
                    reason_parts.append("anonymous-auth가 false로 설정되지 않음")
                if not sa_lookup_ok:
                    reason_parts.append("service-account-lookup가 true로 설정되지 않음")
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": name,
                    "Namespace": "kube-system",
                    "Reason": "; ".join(reason_parts),
                    "Evidence": {"args": args_list},
                    "Remediation": "Control plane 노드의 kube-apiserver manifest (/etc/kubernetes/manifests/kube-apiserver.yaml)에서 --anonymous-auth=false, --service-account-lookup=true 로 설정 후 kube-apiserver 재시작"
                })
        return findings
