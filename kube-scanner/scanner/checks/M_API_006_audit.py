# 보안 점검 항목: API Server 로그 관리
# scanner/checks/api_server_audit.py
from .base import Check
import subprocess, json, traceback

class APIServerAuditCheck(Check):
    id = "CHK-M-API-006"
    name = "로그 관리"
    category = "ControlPlane"
    severity = "High"
    points = 7
    risk_level = 7
    description = "로그 정보는 침해 사고 발생시 해킹의 흔적 및 공격기법을 확인할 수 있는 중요 자료로 정기적인 로그 분석을 통하여 시스템 침입 흔적을 확인할 수 있다."
    recommended_setting = "API server 로그가 활성화된 경우\n- --audit-log-path\n- --audit-policy-file\n- --audit-log-maxage\n- --audit-log-maxbackup\n- --audit-log-maxsize"
    verification_command = "kubectl get pods -n kube-system -o json | jq '.items[] | select(.metadata.name | contains(\"kube-apiserver\")) | .spec.containers[].args' | grep -E 'audit-log|audit-policy'"

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
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "ObjectType": "Cluster",
                "ObjectName": "control-plane",
                "Namespace": "N/A",
                "Reason": "kube-apiserver 파드를 찾을 수 없음 (관리형 컨트롤플레인 또는 검사 대상 없음)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "자체 운영 클러스터면 kube-system에 kube-apiserver 파드 존재 여부 확인"
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
                    "Result": "PASS",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "감사 로그 필수 설정 완료; 로테이션 옵션(" + ", ".join(weak_rotation) + ") 추가 권장",
                    "Evidence": {"args": args_list, "flag_values": flag_values},
                    "Remediation": "선택: --audit-log-maxage, --audit-log-maxbackup, --audit-log-maxsize 로 로테이션 설정"
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
