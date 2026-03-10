# 보안 점검 항목: Kubelet 커널 파라미터 설정
# scanner/checks/kubelet_kernel.py
from .base import Check
import subprocess, json, traceback

class KubeletKernelCheck(Check):
    id = "CHK-W-KUBELET-004"
    name = "Kubelet 커널 파라미터 설정 검사"
    category = "Kubelet"
    severity = "Medium"
    points = 2
    risk_level = 6
    description = "Kubelet이 실행되는 노드의 커널 파라미터가 적절히 설정되어야 합니다. 특히 네트워크 및 보안 관련 파라미터는 컨테이너 격리와 보안에 중요합니다."
    recommended_setting = "커널 파라미터가 적절히 설정된 경우\n- net.ipv4.ip_forward=1\n- net.bridge.bridge-nf-call-iptables=1\n- kernel.panic_on_oops=1"
    verification_command = "sysctl net.ipv4.ip_forward\nsysctl net.bridge.bridge-nf-call-iptables\nsysctl kernel.panic_on_oops"

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def run(self, kubeconfig='', node_scanner_data=None):
        """
        node-scanner DaemonSet 로그가 있으면 노드별 sysctl 값을 자동 판정합니다.
        없으면 기존대로 노드별 WARN(직접 접근 필요)로 처리합니다.
        """
        
        try:
            # 노드 목록 가져오기
            res = self._kubectl(["get", "nodes", "-o", "json"], kubeconfig)
            if res.returncode != 0:
                return [{
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "Reason": "kubectl 실행 실패: " + (res.stderr or res.stdout).strip(),
                    "Evidence": {},
                    "Remediation": "kubectl 접근 권한 확인"
                }]
            
            nodes = json.loads(res.stdout)
            node_items = nodes.get("items", [])
            
            if not node_items:
                return [{
                    "CheckID": self.id,
                    "Result": "WARN",
                    "Reason": "노드를 찾을 수 없음",
                    "Evidence": {},
                    "Remediation": "클러스터에 노드가 있는지 확인하세요"
                }]

            expected = {
                "net.ipv4.ip_forward": "1",
                "net.bridge.bridge-nf-call-iptables": "1",
                "kernel.panic_on_oops": "1",
            }

            # node-scanner 데이터가 있으면 노드별로 직접 판정
            if isinstance(node_scanner_data, dict) and node_scanner_data.get("available"):
                ns_nodes = (node_scanner_data.get("nodes") or {})
                results = []

                for node in node_items:
                    node_name = node.get("metadata", {}).get("name", "unknown")
                    node_info = node.get("status", {}).get("nodeInfo", {})
                    kernel_version = node_info.get("kernelVersion", "unknown")

                    nd = ns_nodes.get(node_name) or {}
                    sysctls = nd.get("sysctls") or {}
                    mismatches = {}
                    missing = []
                    for k, vexp in expected.items():
                        v = (sysctls.get(k) or "").strip()
                        if v == "":
                            missing.append(k)
                        elif v != vexp:
                            mismatches[k] = {"expected": vexp, "actual": v}

                    if mismatches:
                        status = "FAIL"
                        reason = "커널 파라미터가 권장값과 다름"
                    elif missing:
                        status = "WARN"
                        reason = f"커널 파라미터 일부를 확인할 수 없음: {', '.join(missing)}"
                    else:
                        status = "PASS"
                        reason = "커널 파라미터가 권장값으로 설정됨"

                    results.append({
                        "CheckID": self.id,
                        "Result": status,
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": reason,
                        "Evidence": {
                            "node": node_name,
                            "kernel_version": kernel_version,
                            "pod": nd.get("pod"),
                            "sysctls": {k: (sysctls.get(k) or "").strip() for k in expected.keys()},
                            "mismatches": mismatches,
                            "missing": missing,
                            "error": nd.get("error"),
                        },
                        "Remediation": (
                            "다음 커널 파라미터를 권장값(1)로 설정하세요:\n"
                            "- net.ipv4.ip_forward\n"
                            "- net.bridge.bridge-nf-call-iptables\n"
                            "- kernel.panic_on_oops\n"
                        )
                    })

                return results

            # fallback: node-scanner 없음 – 노드별로 직접 확인 안내만 제공
            results = []
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                kernel_version = node_info.get("kernelVersion", "unknown")
                results.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Node",
                    "ObjectName": node_name,
                    "Namespace": "N/A",
                    "Reason": "커널 파라미터를 자동으로 확인할 수 없음 (node-scanner DaemonSet 필요)",
                    "Evidence": {
                        "node": node_name,
                        "kernel_version": kernel_version,
                        "expected": expected,
                        "node_scanner_error": (node_scanner_data or {}).get("error") if isinstance(node_scanner_data, dict) else None
                    },
                    "Remediation": (
                        "노드에 직접 접속하여 다음을 확인/설정하세요:\n"
                        "sysctl net.ipv4.ip_forward\n"
                        "sysctl net.bridge.bridge-nf-call-iptables\n"
                        "sysctl kernel.panic_on_oops\n"
                    )
                })

            return results
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "kubectl get nodes 명령을 직접 실행하여 확인하세요"
            }]

