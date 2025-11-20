# 보안 점검 항목: API Server 로그 관리
# scanner/checks/api_server_audit.py
from .base import Check
import subprocess, json, traceback

class APIServerAuditCheck(Check):
    id = "CHK-M-API-006"
    name = "API Server 감사(audit) 로그 설정 검사"
    category = "ControlPlane"
    severity = "High"
    points = 6

    FLAGS = [
        "--audit-log-path",
        "--audit-policy-file",
        "--audit-log-maxage",
        "--audit-log-maxbackup",
        "--audit-log-maxsize"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        """flag_name 형태: '--audit-log-path'
           반환: 값(str) 또는 None(플래그 없음)"""
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=",1)[1]
            if a == flag_name:
                if i + 1 < len(args_list):
                    return args_list[i+1]
                return None
        return None

    def run(self, kubeconfig=''):
        try:
            res = self._kubectl(["get","pods","-n","kube-system","-o","json"], kubeconfig)
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

        # kube-apiserver 파드 수집
        apiserver_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name","")
            if "kube-apiserver" in name:
                apiserver_pods.append(it)

        if not apiserver_pods:
            # 관리형 컨트롤플레인일 가능성 또는 권한 부족
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 가능성 또는 권한 부족)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "관리형 클러스터이면 제공자 문서/콘솔에서 감사 로그 설정 확인"
            }]

        findings = []
        for p in apiserver_pods:
            meta = p.get("metadata",{})
            pod_name = meta.get("name")
            spec = p.get("spec",{}) or {}
            containers = spec.get("containers",[]) or []

            args_list = []
            for c in containers:
                if c.get("command"):
                    args_list += c.get("command")
                if c.get("args"):
                    args_list += c.get("args")

            # 플래그 값 추출
            flag_values = {f: self._extract_flag(args_list,f) for f in self.FLAGS}

            missing_required = []
            weak_rotation = []
            # --audit-log-path, --audit-policy-file 은 필수로 존재하고 비어있지 않아야 함
            if not flag_values.get("--audit-log-path"):
                missing_required.append("--audit-log-path")
            if not flag_values.get("--audit-policy-file"):
                missing_required.append("--audit-policy-file")

            # 로테이션/보존 관련은 권고: 값이 없으면 WARN
            for opt in ("--audit-log-maxage","--audit-log-maxbackup","--audit-log-maxsize"):
                v = flag_values.get(opt)
                if v is None or (isinstance(v,str) and v.strip()==""):
                    weak_rotation.append(opt)

            # 판단
            if missing_required:
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "감사 로그 필수 플래그 누락: " + ", ".join(missing_required),
                    "Evidence": {"args": args_list, "flag_values": flag_values},
                    "Remediation": (
                        "kube-apiserver 매니페스트에 --audit-log-path, --audit-policy-file 을 설정하세요. "
                        "또한 장기 보관과 디스크 관리를 위해 --audit-log-maxage/--audit-log-maxbackup/--audit-log-maxsize 등 로테이션 옵션을 설정하세요."
                    )
                })
            elif weak_rotation:
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "감사 로그 보전/로테이션 관련 설정 부재(권고): " + ", ".join(weak_rotation),
                    "Evidence": {"args": args_list, "flag_values": flag_values},
                    "Remediation": "디스크 사용량과 조사 요건에 따라 --audit-log-maxage, --audit-log-maxbackup, --audit-log-maxsize 값을 설정하여 로그 롤링/보존 정책을 마련하세요."
                })
            else:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "감사 로그 플래그 및 로테이션/보존 설정이 존재함",
                    "Evidence": {"flag_values": flag_values},
                    "Remediation": ""
                })

        return findings
