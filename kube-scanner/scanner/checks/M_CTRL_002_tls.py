# 보안 점검 항목: Controller Manager SSL/TLS 적용
# scanner/checks/controller_manager_tls.py
from .base import Check
import subprocess, json, traceback

class ControllerManagerTLSCheck(Check):
    id = "CHK-M-CTRL-002"
    name = "Controller Manager SSL/TLS 설정 검사"
    category = "ControlPlane"
    severity = "High"
    points = 7

    FLAGS = [
        "--root-ca-file",
        "--feature-gates"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        """flag_name 예: '--root-ca-file'"""
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=",1)[1]
            if a == flag_name:
                if i + 1 < len(args_list) and not args_list[i+1].startswith("--"):
                    return args_list[i+1]
                # 단독 플래그이면 'present' 반환
                return "present"
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

        # kube-controller-manager 파드 수집
        cm_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-controller-manager" in name:
                cm_pods.append(it)

        if not cm_pods:
            # 관리형 컨트롤플레인(EKS, GKE, AKS, kind 등)은 kube-controller-manager 파드가 없음.
            # TLS는 클라우드 제공자가 관리하므로 이 검사 항목은 적용 대상이 아님 → PASS
            return [{
                "CheckID": self.id,
                "Result": "PASS",
                "ObjectType": "Cluster",
                "ObjectName": "control-plane",
                "Namespace": "N/A",
                "Reason": "관리형 컨트롤플레인으로 kube-controller-manager 파드가 없음 (TLS는 플랫폼에서 관리)",
                "Evidence": {
                    "note": "자체 운영 컨트롤플레인이면 kube-system에 kube-controller-manager 파드가 있어야 함",
                    "kube_system_pod_count": len(pods.get("items", []))
                },
                "Remediation": ""
            }]

        findings = []
        for p in cm_pods:
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

            root_ca = self._extract_flag(args_list, "--root-ca-file")
            feature_gates = self._extract_flag(args_list, "--feature-gates")

            reasons = []
            result = "PASS"

            # root-ca-file 판정: 반드시 존재하고 값(경로)이 있어야 함
            if root_ca is None or (isinstance(root_ca, str) and root_ca.strip() == ""):
                reasons.append("--root-ca-file 플래그가 없거나 값이 비어있음 (권장: CA 경로 지정)")
                result = "FAIL"
            else:
                # 값이 'present'면 경고 (경로가 있어야 함)
                if root_ca == "present":
                    reasons.append("--root-ca-file 플래그가 단독으로 존재 (경로 지정 필요)")
                    result = "FAIL"

            # feature-gates 판정: 권장(있으면 PASS), 없으면 WARN
            if feature_gates is None:
                reasons.append("--feature-gates 플래그가 없음 (권장: TLS/회전 관련 기능 활성화 여부 확인)")
                if result != "FAIL":
                    result = "WARN"
            else:
                # 비어 있거나 'present'인 경우는 WARN
                if feature_gates == "present" or (isinstance(feature_gates, str) and feature_gates.strip() == ""):
                    reasons.append("--feature-gates 값이 비어있거나 단독 플래그임 (구성 확인 권장)")
                    if result != "FAIL":
                        result = "WARN"
                else:
                    # 값이 있으면 PASS 조건에 기여 (예: "RotateKubeletClientCertificate=true,..." 등)
                    pass

            findings.append({
                "CheckID": self.id,
                "Result": result,
                "ObjectType": "Pod",
                "ObjectName": pod_name,
                "Namespace": "kube-system",
                "Reason": "; ".join(reasons) if reasons else "Controller Manager TLS 관련 설정(루트 CA 및 feature-gates)이 적절히 구성됨",
                "Evidence": {"args": args_list, "root_ca_file": root_ca, "feature_gates": feature_gates},
                "Remediation": (
                    "kube-controller-manager 매니페스트에서 --root-ca-file=/path/to/ca.crt 를 설정하여 신뢰할 CA를 지정하세요. "
                    "또한 TLS 관련/자동갱신 기능(예: RotateKubeletClientCertificate 등)이 필요하면 --feature-gates에 적절한 값을 추가하세요. "
                    "파일 존재/권한 확인은 control-plane 노드에서 직접 수행하십시오."
                )
            })

        return findings
