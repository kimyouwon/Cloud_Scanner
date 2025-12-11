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

    def run(self, kubeconfig=''):
        findings = []
        
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
            
            # 각 노드의 커널 파라미터 확인
            # 노드에 직접 접근이 어려우므로 WARN으로 처리
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                kernel_version = node_info.get("kernelVersion", "unknown")
                
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Node",
                    "ObjectName": node_name,
                    "Namespace": "N/A",
                    "Reason": "커널 파라미터를 자동으로 확인할 수 없음 (노드에 직접 접근 필요)",
                    "Evidence": {
                        "node": node_name,
                        "kernel_version": kernel_version
                    },
                    "Remediation": (
                        f"노드 {node_name}에 직접 접근하여 다음 커널 파라미터를 확인하세요:\n\n"
                        "1. IP forwarding 확인:\n"
                        "   sysctl net.ipv4.ip_forward\n"
                        "   (권장: 1)\n\n"
                        "2. Bridge netfilter 확인:\n"
                        "   sysctl net.bridge.bridge-nf-call-iptables\n"
                        "   (권장: 1)\n\n"
                        "3. Kernel panic on oops 확인:\n"
                        "   sysctl kernel.panic_on_oops\n"
                        "   (권장: 1)\n\n"
                        "설정 방법:\n"
                        "sudo sysctl -w net.ipv4.ip_forward=1\n"
                        "sudo sysctl -w net.bridge.bridge-nf-call-iptables=1\n"
                        "sudo sysctl -w kernel.panic_on_oops=1\n\n"
                        "영구 적용:\n"
                        "echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf\n"
                        "echo 'net.bridge.bridge-nf-call-iptables=1' | sudo tee -a /etc/sysctl.conf\n"
                        "echo 'kernel.panic_on_oops=1' | sudo tee -a /etc/sysctl.conf"
                    )
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "kubectl get nodes 명령을 직접 실행하여 확인하세요"
            }]
        
        return findings
