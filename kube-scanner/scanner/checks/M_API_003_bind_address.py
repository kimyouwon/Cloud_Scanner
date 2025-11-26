# 보안 점검 항목: API Server 서비스 API 외부 오픈 금지
# scanner/checks/control_plane_bind_address.py
from .base import Check
import subprocess, json

class ControlPlaneBindAddressCheck(Check):
    id = "CHK-M-API-003"
    name = "Control Plane bind-address (Scheduler / ControllerManager) 검사"
    category = "ControlPlane"
    severity = "High"
    points = 6
    risk_level = 9
    description = "API Server의 서비스 API가 외부에서 접근 가능할 경우, Kubernetes 시스템의 모든 요소에 영향을 줄 수 있으므로 클러스터의 공격을 최소화하기 위해 로컬호스트 인터페이스에만 바인딩 설정을 해야 한다."
    recommended_setting = "API server 서비스 API가 외부에서 접근 불가능한 경우\n- --bind-address=127.0.0.1 (kube-scheduler, kube-controller-manager)"
    verification_command = "/etc/kubernetes/manifests/kube-scheduler.yaml 파일 내 --bind-address 파라미터 값 확인\n/etc/kubernetes/manifests/kube-controller-manager.yaml 파일 내 --bind-address 파라미터 값 확인"

    SAFE_VALUES = {"127.0.0.1", "localhost", "::1"}

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_bind_addr(self, args_list):
        """
        args_list: list of args/command entries
        반환: None(플래그 없음) or str(value) (예: '127.0.0.1' 또는 '0.0.0.0')
        """
        for i, a in enumerate(args_list):
            if a.startswith("--bind-address="):
                return a.split("=", 1)[1]
            if a == "--bind-address":
                # 다음 항목이 값일 수 있음
                if i + 1 < len(args_list):
                    return args_list[i+1]
        return None

    def run(self, kubeconfig=''):
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

        # 체크 대상 이름들
        targets = ["kube-scheduler", "kube-controller-manager"]
        findings = []

        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            for t in targets:
                if t in name:
                    containers = (it.get("spec", {}) or {}).get("containers", []) or []
                    args_list = []
                    for c in containers:
                        if c.get("command"):
                            args_list += c.get("command")
                        if c.get("args"):
                            args_list += c.get("args")

                    bind_val = self._extract_bind_addr(args_list)
                    if bind_val is None:
                        # 플래그 없음 -> WARN: 기본값이 안전할 수 있으나 확인 권고
                        findings.append({
                            "CheckID": self.id,
                            "Result": "WARN",
                            "ObjectType": "Pod",
                            "ObjectName": name,
                            "Namespace": "kube-system",
                            "Reason": "--bind-address 플래그가 없음 (기본값 확인 필요)",
                            "Evidence": {"args": args_list},
                            "Remediation": "매니페스트(/etc/kubernetes/manifests/...)에서 --bind-address를 명시적으로 설정(권장: 127.0.0.1 또는 내부 전용 IP)"
                        })
                    else:
                        # 값이 안전한지 검사
                        # normalize: IPv4/IPv6 / 'localhost'
                        bv = bind_val.strip().lower()
                        if bv in self.SAFE_VALUES:
                            findings.append({
                                "CheckID": self.id,
                                "Result": "PASS",
                                "ObjectType": "Pod",
                                "ObjectName": name,
                                "Namespace": "kube-system",
                                "Reason": f"--bind-address={bind_val} (안전)",
                                "Evidence": {"args": args_list},
                                "Remediation": ""
                            })
                        elif bv == "0.0.0.0":
                            findings.append({
                                "CheckID": self.id,
                                "Result": "FAIL",
                                "ObjectType": "Pod",
                                "ObjectName": name,
                                "Namespace": "kube-system",
                                "Reason": f"--bind-address={bind_val} (모든 인터페이스에 바인딩 되어 외부 접근 가능)",
                                "Evidence": {"args": args_list},
                                "Remediation": "매니페스트에서 --bind-address=127.0.0.1 (또는 내부 전용 IP)로 변경하고 kubelet이 재시작하도록 함"
                            })
                        else:
                            # 내부 사설 IP 등은 허용 가능하므로 WARN 또는 PASS 정책 선택 가능.
                            # 여기서는 내부 전용(127.,10.,172.16-31,192.168.)이면 PASS로, 그 외는 WARN으로 처리
                            if bv.startswith("127.") or bv.startswith("10.") or bv.startswith("192.168.") or bv.startswith("172."):
                                findings.append({
                                    "CheckID": self.id,
                                    "Result": "PASS",
                                    "ObjectType": "Pod",
                                    "ObjectName": name,
                                    "Namespace": "kube-system",
                                    "Reason": f"--bind-address={bind_val} (사설/로컬 인터페이스로 바인딩되어 안전한 것으로 보임)",
                                    "Evidence": {"args": args_list},
                                    "Remediation": ""
                                })
                            else:
                                findings.append({
                                    "CheckID": self.id,
                                    "Result": "WARN",
                                    "ObjectType": "Pod",
                                    "ObjectName": name,
                                    "Namespace": "kube-system",
                                    "Reason": f"--bind-address={bind_val} (검토 필요: 외부 접근 허용 여부 확인)",
                                    "Evidence": {"args": args_list},
                                    "Remediation": "바인딩 주소가 공인 IP이면 방화벽/접근제어로 외부 접근 차단 또는 localhost로 변경"
                                })
        if not findings:
            # 관련 파드 자체를 못찾은 경우 (managed control plane 등)
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-scheduler 또는 kube-controller-manager 파드가 kube-system에서 발견되지 않음 (관리형 컨트롤플레인 혹은 권한 부족)",
                "Evidence": {"pod_count": len(pods.get("items", []))},
                "Remediation": "컨트롤플레인 매니페스트나 클라우드 문서 확인"
            }]
        return findings
