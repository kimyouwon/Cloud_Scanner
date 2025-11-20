# 보안 점검 항목: etcd SSL/TLS 적용
# scanner/checks/etcd_tls.py
from .base import Check
import subprocess, json, traceback

class EtcdTLSCheck(Check):
    id = "CHK-M-ETCD-002"
    name = "etcd SSL/TLS 적용 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    # etcd 서버 측 TLS 플래그
    ETCD_SERVER_FLAGS = [
        "--client-cert-auth",      # 클라이언트 인증서 인증 활성화
        "--cert-file",              # etcd 서버 인증서 파일
        "--key-file",               # etcd 서버 키 파일
        "--peer-cert-file",         # etcd 피어 간 통신 인증서
        "--peer-key-file",          # etcd 피어 간 통신 키
        "--trusted-ca-file",        # 신뢰할 CA 파일
        "--auto-tls",               # 자동 TLS (권장하지 않음)
        "--peer-auto-tls"           # 피어 자동 TLS (권장하지 않음)
    ]

    # kube-apiserver의 etcd 연결 TLS 플래그
    APISERVER_ETCD_FLAGS = [
        "--etcd-certfile",          # etcd 클라이언트 인증서
        "--etcd-keyfile",           # etcd 클라이언트 키
        "--etcd-cafile"             # etcd CA 파일
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        """
        args_list: list of args strings
        flag_name: e.g., '--cert-file'
        반환: None(플래그 없음) or str(값) or 'present'(플래그만 존재)
        """
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=", 1)[1]
            if a == flag_name:
                # 다음 토큰이 값일 수 있음
                if i + 1 < len(args_list) and not args_list[i+1].startswith("--"):
                    return args_list[i+1]
                # 단독 플래그이면 'present' 반환
                return "present"
        return None

    def _check_etcd_pod(self, pod, kubeconfig=''):
        """etcd 파드의 TLS 설정 확인"""
        meta = pod.get("metadata", {})
        pod_name = meta.get("name")
        spec = pod.get("spec", {}) or {}
        containers = spec.get("containers", []) or []

        args_list = []
        for c in containers:
            if c.get("command"):
                args_list += c.get("command")
            if c.get("args"):
                args_list += c.get("args")

        findings = []
        missing_flags = []
        unsafe_flags = []
        flag_values = {}

        # 각 플래그 확인
        for flag in self.ETCD_SERVER_FLAGS:
            val = self._extract_flag(args_list, flag)
            flag_values[flag] = val

            if flag in ["--auto-tls", "--peer-auto-tls"]:
                # auto-tls는 권장하지 않음
                if val is not None and val not in ("false", "0", "no"):
                    unsafe_flags.append(f"{flag}={val} (자동 TLS는 권장하지 않음)")
            else:
                # 필수 플래그는 값이 있어야 함
                if val is None or val == "":
                    missing_flags.append(flag)
                elif val == "present" and flag in ["--cert-file", "--key-file", "--trusted-ca-file"]:
                    # 값이 필요한 플래그인데 값이 없음
                    missing_flags.append(f"{flag} (값 없음)")

        # client-cert-auth는 true여야 함
        client_cert_auth = self._extract_flag(args_list, "--client-cert-auth")
        if client_cert_auth is None or client_cert_auth.lower() not in ("true", "1", "yes"):
            missing_flags.append("--client-cert-auth=true")

        # 결과 판정
        if missing_flags or unsafe_flags:
            reasons = []
            if missing_flags:
                reasons.append(f"필수 TLS 플래그 누락: {', '.join(missing_flags)}")
            if unsafe_flags:
                reasons.append(f"안전하지 않은 설정: {', '.join(unsafe_flags)}")
            
            findings.append({
                "CheckID": self.id,
                "Result": "FAIL" if missing_flags else "WARN",
                "ObjectType": "Pod",
                "ObjectName": pod_name,
                "Namespace": "kube-system",
                "Reason": "; ".join(reasons),
                "Evidence": {"args": args_list, "flag_values": flag_values},
                "Remediation": (
                    "etcd 파드 매니페스트에 다음 TLS 플래그를 설정하세요:\n"
                    "- --client-cert-auth=true (클라이언트 인증서 인증)\n"
                    "- --cert-file=/path/to/server.crt (서버 인증서)\n"
                    "- --key-file=/path/to/server.key (서버 키)\n"
                    "- --trusted-ca-file=/path/to/ca.crt (신뢰할 CA)\n"
                    "- --peer-cert-file, --peer-key-file (피어 간 통신용, 클러스터 구성 시)\n"
                    "주의: --auto-tls, --peer-auto-tls는 사용하지 마세요."
                )
            })
        else:
            findings.append({
                "CheckID": self.id,
                "Result": "PASS",
                "ObjectType": "Pod",
                "ObjectName": pod_name,
                "Namespace": "kube-system",
                "Reason": "etcd 서버에 TLS 설정이 적절히 구성됨",
                "Evidence": {"flag_values": flag_values},
                "Remediation": ""
            })

        return findings

    def _check_apiserver_etcd_connection(self, pod, kubeconfig=''):
        """kube-apiserver의 etcd 연결 TLS 설정 확인"""
        meta = pod.get("metadata", {})
        pod_name = meta.get("name")
        spec = pod.get("spec", {}) or {}
        containers = spec.get("containers", []) or []

        args_list = []
        for c in containers:
            if c.get("command"):
                args_list += c.get("command")
            if c.get("args"):
                args_list += c.get("args")

        findings = []
        missing_flags = []
        flag_values = {}

        # kube-apiserver의 etcd 연결 플래그 확인
        for flag in self.APISERVER_ETCD_FLAGS:
            val = self._extract_flag(args_list, flag)
            flag_values[flag] = val
            if val is None or val == "":
                missing_flags.append(flag)

        if missing_flags:
            findings.append({
                "CheckID": self.id,
                "Result": "FAIL",
                "ObjectType": "Pod",
                "ObjectName": pod_name,
                "Namespace": "kube-system",
                "Reason": f"kube-apiserver의 etcd 연결 TLS 플래그 누락: {', '.join(missing_flags)}",
                "Evidence": {"args": args_list, "flag_values": flag_values},
                "Remediation": (
                    "kube-apiserver 매니페스트에 etcd 연결용 TLS 플래그를 설정하세요:\n"
                    "- --etcd-certfile=/path/to/etcd-client.crt\n"
                    "- --etcd-keyfile=/path/to/etcd-client.key\n"
                    "- --etcd-cafile=/path/to/etcd-ca.crt"
                )
            })
        else:
            findings.append({
                "CheckID": self.id,
                "Result": "PASS",
                "ObjectType": "Pod",
                "ObjectName": pod_name,
                "Namespace": "kube-system",
                "Reason": "kube-apiserver의 etcd 연결 TLS 설정이 적절히 구성됨",
                "Evidence": {"flag_values": flag_values},
                "Remediation": ""
            })

        return findings

    def run(self, kubeconfig=''):
        try:
            res = self._kubectl(["get", "pods", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode != 0:
                return [{
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "Reason": "kubectl 실행 실패: " + (res.stderr or res.stdout).strip(),
                    "Evidence": {},
                    "Remediation": "kubectl 접근 권한(특히 kube-system 조회) 확인"
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

        findings = []
        
        # etcd 파드 찾기
        etcd_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            # etcd 파드는 보통 "etcd-" 로 시작하거나 "etcd" 포함
            if "etcd" in name.lower() and "kube-apiserver" not in name:
                etcd_pods.append(it)

        # kube-apiserver 파드 찾기
        apiserver_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-apiserver" in name:
                apiserver_pods.append(it)

        # etcd 파드 TLS 설정 확인
        if etcd_pods:
            for etcd_pod in etcd_pods:
                findings.extend(self._check_etcd_pod(etcd_pod, kubeconfig))
        else:
            # etcd 파드를 찾지 못함 (외부 etcd 또는 관리형 클러스터)
            findings.append({
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 etcd 파드를 찾지 못함 (외부 etcd 또는 관리형 컨트롤플레인일 수 있음)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": (
                    "etcd가 외부에서 실행되거나 관리형 클러스터인 경우, etcd 서버의 TLS 설정을 직접 확인하세요:\n"
                    "- --client-cert-auth=true\n"
                    "- --cert-file, --key-file, --trusted-ca-file 설정\n"
                    "- --peer-cert-file, --peer-key-file (클러스터 구성 시)"
                )
            })

        # kube-apiserver의 etcd 연결 TLS 설정 확인
        if apiserver_pods:
            for apiserver_pod in apiserver_pods:
                findings.extend(self._check_apiserver_etcd_connection(apiserver_pod, kubeconfig))
        else:
            findings.append({
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 수 있음 또는 권한 부족)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "관리형 클러스터이면 클라우드 콘솔/문서 확인. 자체관리라면 컨트롤플레인에서 매니페스트 확인"
            })

        if not findings:
            # 아무것도 찾지 못한 경우
            findings.append({
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "etcd 및 kube-apiserver 파드를 찾지 못함",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "컨트롤플레인 구성 확인"
            })

        return findings




