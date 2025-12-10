# 보안 점검 항목: API Server SSL/TLS 적용
# scanner/checks/api_server_tls.py
from .base import Check
import subprocess, json, traceback

class APIServerTLSCheck(Check):
    id = "CHK-M-API-005"
    name = "API Server SSL/TLS 설정 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 5
    risk_level = 9
    description = "SSL/TLS 통신 적용을 통해 네트워크 스니핑과 같은 공격으로 주요 정보가 노출되지 않도록 안전한 통신을 해야 하며, API server에 접근하는 대상에 대해 검증할 수 있도록 설정해야 한다. 또한 SSL/TLS 통신 적용 시에는 주기적으로 인증서를 변경하고 안전한 버전의 암호화 방식을 사용하는 방법을 통해 위험을 최소화할 수 있는 정책 설정이 필요하다."
    recommended_setting = "API server SSL/TLS가 적용된 경우\n- --secure-port 설정\n- --kubelet-certificate-authority\n- --kubelet-client-certificate\n- --kubelet-client-key\n- --tls-cert-file\n- --tls-private-key-file\n- --client-ca-file\n- --tls-cipher-suites"
    verification_command = "kubectl get pods -n kube-system -o json | jq '.items[] | select(.metadata.name | contains(\"kube-apiserver\")) | .spec.containers[].args' | grep -E 'secure-port|tls-cert|tls-private-key|client-ca'"

    # 필수 TLS 플래그 (PASS를 위해 반드시 필요)
    REQUIRED_TLS_FLAGS = [
        "--tls-cert-file",
        "--tls-private-key-file"
    ]
    
    # 권장 TLS 플래그 (없으면 WARN)
    RECOMMENDED_TLS_FLAGS = [
        "--client-ca-file",
        "--secure-port"
    ]
    
    # 선택적 TLS 플래그 (없어도 OK, 있으면 체크)
    OPTIONAL_TLS_FLAGS = [
        "--kubelet-certificate-authority",
        "--kubelet-client-certificate",
        "--kubelet-client-key",
        "--kubelet-account-key-file",
        "--tls-cipher-suites"
    ]
    
    # 모든 TLS 플래그 (참고용)
    TLS_FLAGS = REQUIRED_TLS_FLAGS + RECOMMENDED_TLS_FLAGS + OPTIONAL_TLS_FLAGS

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

            missing_required = []
            missing_recommended = []
            weak_cipher_detected = False
            insecure_port = False
            flag_values = {}

            # 모든 플래그 값 추출
            for f in self.TLS_FLAGS:
                val = self._extract_flag(args_list, f)
                flag_values[f] = val

            # 필수 플래그 체크
            for f in self.REQUIRED_TLS_FLAGS:
                val = flag_values.get(f)
                if val is None or (isinstance(val, str) and val.strip() == ""):
                    missing_required.append(f)

            # 권장 플래그 체크
            for f in self.RECOMMENDED_TLS_FLAGS:
                val = flag_values.get(f)
                if val is None or (isinstance(val, str) and val.strip() == ""):
                    missing_recommended.append(f)

            # secure-port check (명시적으로 0이 아니면 OK, 기본값 6443 사용)
            sp = flag_values.get("--secure-port")
            if sp is not None:
                try:
                    if int(sp) == 0:
                        insecure_port = True
                except Exception:
                    # non-int: warn
                    insecure_port = True
            # secure-port가 없으면 기본값(6443) 사용하므로 OK

            # cipher suites weakness check
            ciphers = flag_values.get("--tls-cipher-suites")
            if ciphers and self._contains_weak_cipher(ciphers):
                weak_cipher_detected = True

            # Decide result
            if missing_required or insecure_port:
                # 필수 플래그가 없거나 secure-port가 0이면 FAIL
                details = []
                if missing_required:
                    details.append("다음 필수 TLS 플래그가 누락되었거나 값이 비어있음: " + ", ".join(missing_required))
                if insecure_port:
                    details.append("--secure-port 가 0으로 설정됨 (TLS 미사용)")
                if missing_recommended:
                    details.append("다음 권장 TLS 플래그가 설정되지 않음: " + ", ".join(missing_recommended))
                if weak_cipher_detected:
                    details.append("--tls-cipher-suites 에 약한 암호화 알고리즘이 포함됨(권고하지 않음)")
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "; ".join(details),
                    "Evidence": {"args": args_list, "flag_values": flag_values},
                    "Remediation": (
                        "kube-apiserver 매니페스트에 필수 TLS 플래그(--tls-cert-file, --tls-private-key-file)를 설정하세요. "
                        "권장 플래그(--client-ca-file, --secure-port)도 설정하는 것을 권장합니다. "
                        "또한 --tls-cipher-suites 에 강력한 TLS1.2/1.3 기반 암호화 스위트만 허용하세요."
                    )
                })
            elif missing_recommended or weak_cipher_detected:
                # 필수는 있지만 권장이 없거나 약한 암호화면 WARN
                details = []
                if missing_recommended:
                    details.append("다음 권장 TLS 플래그가 설정되지 않음: " + ", ".join(missing_recommended))
                if weak_cipher_detected:
                    details.append("--tls-cipher-suites 에 약한 암호화 알고리즘이 포함됨(권고하지 않음)")
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "; ".join(details),
                    "Evidence": {"args": args_list, "flag_values": flag_values},
                    "Remediation": (
                        "권장 TLS 플래그(--client-ca-file, --secure-port)를 설정하는 것을 권장합니다. "
                        "또한 --tls-cipher-suites 에 강력한 TLS1.2/1.3 기반 암호화 스위트만 허용하세요."
                    )
                })
            else:
                # 필수 플래그가 모두 있고 secure-port도 OK면 PASS
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "필수 TLS 플래그(--tls-cert-file, --tls-private-key-file)가 설정되어 있음",
                    "Evidence": {"flag_values": flag_values},
                    "Remediation": ""
                })

        return findings
