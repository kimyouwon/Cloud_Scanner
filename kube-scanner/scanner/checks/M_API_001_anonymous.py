# 보안 점검 항목: API Server 비인증 접근 차단
# scanner/checks/api_server_anonymous.py
from .base import Check
import subprocess, json, traceback

class APIServerAnonymousCheck(Check):
    id = "CHK-M-API-001"
    name = "API Server 익명 접근 및 service-account-lookup 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        """
        args_list: list of args strings
        flag_name: e.g., '--anonymous-auth'
        반환: None(플래그 없음) or 'true'/'false' (소문자) or raw token if '--flag=value' 형식
        """
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=", 1)[1].lower()
            if a == flag_name:
                # 다음 토큰이 값일 수 있음
                if i + 1 < len(args_list):
                    return args_list[i+1].lower()
                return None
        return None

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

        # kube-apiserver 관련 파드 수집
        apiserver_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-apiserver" in name:
                apiserver_pods.append(it)

        if not apiserver_pods:
            # 관리형 컨트롤플레인 또는 권한 부족 가능
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 수 있음 또는 권한 부족)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "관리형 클러스터이면 클라우드 콘솔/문서 확인. 자체관리라면 컨트롤플레인에서 매니페스트 확인"
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

            anon_val = self._extract_flag(args_list, "--anonymous-auth")
            sa_lookup_val = self._extract_flag(args_list, "--service-account-lookup")

            # 분석 로직: 명시적으로 --anonymous-auth=false 이면 PASS, true 또는 플래그 없음이면 WARN/FAIL 판단
            # service-account-lookup은 true 권장
            if anon_val is not None:
                if anon_val in ("false", "0", "no"):
                    anon_status = "disabled"
                elif anon_val in ("true", "1", "yes"):
                    anon_status = "enabled"
                else:
                    anon_status = f"unknown({anon_val})"
            else:
                anon_status = "unset"

            if sa_lookup_val is not None:
                if sa_lookup_val in ("true", "1", "yes"):
                    sa_status = "enabled"
                elif sa_lookup_val in ("false", "0", "no"):
                    sa_status = "disabled"
                else:
                    sa_status = f"unknown({sa_lookup_val})"
            else:
                sa_status = "unset"

            # 결과 판단
            # 최우선: anonymous enabled -> FAIL
            if anon_status == "enabled":
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "--anonymous-auth 가 활성화되어 익명 접근 허용됨",
                    "Evidence": {"args": args_list, "anonymous-auth": anon_val, "service-account-lookup": sa_lookup_val},
                    "Remediation": "kube-apiserver 매니페스트(예: /etc/kubernetes/manifests/kube-apiserver.yaml)에서 --anonymous-auth=false 로 변경"
                })
                continue

            # anonymous unset (플래그 없음) -> WARN (기본값 확인 필요)
            if anon_status == "unset":
                # if sa lookup disabled or unset -> 더 위험 -> WARN
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "--anonymous-auth 플래그가 없음(기본값에 따라 익명 접근 허용일 수 있음). 확인 권장",
                    "Evidence": {"args": args_list, "service-account-lookup": sa_lookup_val},
                    "Remediation": "명시적으로 --anonymous-auth=false 설정 및 --service-account-lookup=true 추가 권장"
                })
                continue

            # anonymous disabled => anon_status == "disabled"
            # 이제 service-account-lookup 검사
            if sa_status == "enabled":
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "--anonymous-auth=false 및 --service-account-lookup=true 로 보임 (권장 설정)",
                    "Evidence": {"args": args_list},
                    "Remediation": ""
                })
            else:
                # sa lookup disabled or unset -> WARN (권장: true)
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": f"--anonymous-auth=false 이지만 --service-account-lookup 값이 안전하지 않음({sa_status})",
                    "Evidence": {"args": args_list},
                    "Remediation": "가능하면 --service-account-lookup=true 로 설정하여 서비스어카운트 토큰 검증을 활성화하세요"
                })

        return findings
