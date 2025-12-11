# 보안 점검 항목: Controller 인증 제어
# scanner/checks/controller_auth.py
from .base import Check
import subprocess, json, traceback

class ControllerAuthCheck(Check):
    id = "CHK-M-CTRL-001"
    name = "Controller 인증 제어 (ServiceAccount credentials 사용 및 private key 설정) 검사"
    category = "ControlPlane"
    severity = "High"
    points = 8
    risk_level = 8
    description = "Controller는 클러스터의 상태를 감시하고 현재 상태와 원하는 상태가 일치하도록 관리하는 작업을 한다. 각 컨트롤러에 대해 개별 서비스 계정 자격증명을 사용해 인가된 계정만이 클러스터를 제어할 수 있도록 설정해야한다."
    recommended_setting = "Controller 인증 제어 설정이 적용된 경우\n- --use-service-account-credentials=true\n- --service-account-private-key-file 설정"
    verification_command = "kubectl get pods -n kube-system -o json | jq '.items[] | select(.metadata.name | contains(\"kube-controller-manager\")) | .spec.containers[].args' | grep -E 'use-service-account-credentials|service-account-private-key-file'"

    REQUIRED_FLAGS = [
        "--use-service-account-credentials",
        "--service-account-private-key-file"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        """
        args_list: list of args (strings)
        flag_name: e.g. '--use-service-account-credentials'
        반환:
          - None (플래그 없음)
          - str 값 (플래그가 --flag=value 형식 또는 --flag value 형식일 때)
          - 'present' (플래그가 단독으로 존재할 경우)
        """
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=", 1)[1].lower()
            if a == flag_name:
                # 다음 토큰이 값일 수 있음
                if i + 1 < len(args_list) and not args_list[i+1].startswith("--"):
                    return args_list[i+1].lower()
                return "present"
        return None

    def run(self, kubeconfig=''):
        try:
            res = self._kubectl(["get", "pods", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode != 0:
                return [{
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "Reason": "kubectl 명령 실패: " + (res.stderr or res.stdout).strip(),
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
        ctrl_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-controller-manager" in name:
                ctrl_pods.append(it)

        if not ctrl_pods:
            # 관리형 컨트롤플레인일 가능성 또는 권한 부족
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 kube-controller-manager 파드를 찾지 못함 (관리형 컨트롤플레인 혹은 권한 부족)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "관리형 클러스터면 제공자 문서 확인. 자체 관리면 control-plane 노드의 매니페스트 확인"
            }]

        findings = []
        for p in ctrl_pods:
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

            # 플래그 값 추출
            use_svcacct_val = self._extract_flag(args_list, "--use-service-account-credentials")
            private_key_val = self._extract_flag(args_list, "--service-account-private-key-file")

            # 판단 로직:
            # - use-service-account-credentials: 명시적으로 true / present => PASS; false => FAIL; unset => WARN
            # - private-key-file: 값(경로)이 있어야 PASS; absent/null => FAIL; present but empty => FAIL
            # 결과 요약 메시지 구성
            reasons = []
            result = "PASS"

            # use-service-account-credentials 판정
            if use_svcacct_val is None:
                reasons.append("--use-service-account-credentials 플래그가 없음 (권장: true)")
                result = "WARN" if result != "FAIL" else "FAIL"
            else:
                # present 또는 값이 있는 경우 허용/불허
                if use_svcacct_val in ("true", "1", "yes", "present"):
                    # ok
                    pass
                elif use_svcacct_val in ("false", "0", "no"):
                    reasons.append("--use-service-account-credentials=false 로 설정되어 있음 (권장: true)")
                    result = "FAIL"
                else:
                    # 알 수 없는 값은 WARN
                    reasons.append(f"--use-service-account-credentials 값이 불명확함: {use_svcacct_val}")
                    if result != "FAIL":
                        result = "WARN"

            # private key 파일 판정
            if private_key_val is None or private_key_val == "present":
                reasons.append("--service-account-private-key-file 플래그가 없거나 값이 비어있음")
                result = "FAIL"
            else:
                # 값이 주어졌으면 (경로 문자열) PASS 가능 — 추가 검증(파일 존재/권한)은 control-plane 노드에서만 가능
                if isinstance(private_key_val, str) and private_key_val.strip() != "":
                    # ok
                    pass
                else:
                    reasons.append("--service-account-private-key-file 값이 비어있음")
                    result = "FAIL"

            # 조합된 메시지
            findings.append({
                "CheckID": self.id,
                "Result": result,
                "ObjectType": "Pod",
                "ObjectName": pod_name,
                "Namespace": "kube-system",
                "Reason": "; ".join(reasons) if reasons else "Controller 인증 제어 설정(서비스어카운트 자격증명 + private key)이 적절히 구성됨",
                "Evidence": {"args": args_list, "use_service_account_credentials": use_svcacct_val, "service_account_private_key_file": private_key_val},
                "Remediation": (
                    "컨트롤러에 대해 서비스 계정 자격증명을 사용하도록 설정하고(private key 파일 경로 지정) "
                    "매니페스트에서 --use-service-account-credentials=true 및 --service-account-private-key-file=/path/to/key.pem 와 같이 설정하세요. "
                    "설정 변경은 control-plane 노드의 static manifest (/etc/kubernetes/manifests/...)에서 수행하고 변경 후 kubelet이 매니페스트를 감지해 재시작합니다. "
                    "파일 존재/권한 등은 control-plane 노드에서 직접 확인하여 private key 파일이 안전한 위치에 있고 권한이 제한되어 있는지 확인하세요."
                )
            })

        return findings
