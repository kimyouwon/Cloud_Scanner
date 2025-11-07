# 보안 점검 항목: API Server SSL/TLS 적용
# scanner/checks/api_server_tls.py
from .base import Check
import subprocess, json, traceback

class APIServerTLSCheck(Check):
    id = "CHK-API-TLS-001"
    name = "API Server SSL/TLS 설정 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    TLS_FLAGS = [
        "--secure-port",
        "--kubelet-certificate-authority",
        "--kubelet-client-certificate",
        "--kubelet-client-key",
        "--kubelet-account-key-file",
        "--tls-cert-file",
        "--tls-private-key-file",
        "--client-ca-file",
        "--tls-cipher-suites"
    ]

    WEAK_CIPHER_INDICATORS = ["rc4", "des", "3des", "null", "exp", "md5", "sha1"]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=", 1)[1]
            if a == flag_name:
                if i + 1 < len(args_list):
                    return args_list[i+1]
                return None
        return None

    def _contains_weak_cipher(self, cipher_string):
        if not cipher_string:
            return False
        s = cipher_string.lower()
        for w in self.WEAK_CIPHER_INDICATORS:
            if w in s:
                return True
        return False

    def run(self, kubeconfig=''):
        try:
            res = self._kubectl(["get", "pods", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode != 0:
                return [{
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "Reason": "kubectl 실행 실패: " + (res.stderr or res.stdout).strip(),
                    "Evidence": {},
                    "Remediation": "kubectl 접근 및 kube-system 조회 권한 확인"
                }]
            pods = json.loads(res.stdout)
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "kubectl 출력 파싱 실패: " + str(e),
                "Evidence": {"trace": traceback.format_exc()},
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
                "Reason": "kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 수 있음 또는 권한 부족)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "클러스터가 관리형인지 확인하거나 control-plane 접근 권한 확보"
            }]

        findings = []
        for p in apiserver_pods:
            meta = p.get("metadata", {})
            pod_name = meta.get("name")
            spec = p.get("spec", {}) or {}
            containers = spec.get("containers", []) or []

            args_list = []
            for c in containers:
                if c.get("command"):
                    args_list += c.get("command")
                if c.get("args"):
                    args_list += c.get("args")

            missing_flags = []
            weak_cipher_detected = False
            insecure_port = False
            flag_values = {}

            for f in self.TLS_FLAGS:
                val = self._extract_flag(args_list, f)
                flag_values[f] = val
                if val is None or (isinstance(val, str) and val.strip() == ""):
                    missing_flags.append(f)

            # secure-port check
            sp = flag_values.get("--secure-port")
            if sp is not None:
                try:
                    if int(sp) == 0:
                        insecure_port = True
                except Exception:
                    # non-int: warn
                    insecure_port = True

            # cipher suites weakness check
            ciphers = flag_values.get("--tls-cipher-suites")
            if ciphers and self._contains_weak_cipher(ciphers):
                weak_cipher_detected = True

            # Decide result
            if missing_flags or insecure_port or weak_cipher_detected:
                details = []
                if missing_flags:
                    details.append("다음 TLS 관련 플래그가 누락되었거나 값이 비어있음: " + ", ".join(missing_flags))
                if insecure_port:
                    details.append("--secure-port 가 0 이거나 비정상 값임 (TLS 미사용 가능성)")
                if weak_cipher_detected:
                    details.append("--tls-cipher-suites 에 약한 암호화 알고리즘이 포함됨(권고하지 않음)")
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL" if missing_flags or insecure_port else "WARN",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "; ".join(details),
                    "Evidence": {"args": args_list, "flag_values": flag_values},
                    "Remediation": (
                        "kube-apiserver 매니페스트에 TLS 관련 플래그(예: --tls-cert-file, --tls-private-key-file, "
                        "--client-ca-file, --kubelet-client-certificate/key 등)를 명시적으로 설정하고 "
                        "--secure-port가 0이 아닌 안전한 포트로 설정되어 있는지 확인하세요. "
                        "또한 --tls-cipher-suites 에 강력한 TLS1.2/1.3 기반 암호화 스위트만 허용하세요."
                    )
                })
            else:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "TLS 관련 플래그가 설정되어 있는 것으로 보임",
                    "Evidence": {"flag_values": flag_values},
                    "Remediation": ""
                })

        return findings
