# 보안 점검 항목: 워커 노드 환경설정 파일 권한 설정
# scanner/checks/worker_config_file_permissions.py
from .base import Check
import subprocess, json, traceback

class WorkerConfigFilePermissionsCheck(Check):
    id = "CHK-W-FILE-001"
    name = "워커 노드 환경설정 파일 권한 설정 검사"
    category = "File"
    severity = "High"
    points = 2
    risk_level = 7
    description = "워커 노드의 Kubernetes 환경설정 파일 접근 권한이 과도하게 설정된 경우, 비인가자가 설정을 변경할 수 있습니다. 따라서 파일의 접근 권한을 제한해야 합니다."
    recommended_setting = "환경설정 파일의 소유자 및 소유 그룹이 root이고, 접근 권한이 644 이하로 설정된 경우"
    verification_command = "ls -al /var/lib/kubelet/config.yaml\nls -al /etc/kubernetes/kubelet.conf"

    # 확인할 환경설정 파일 목록 (워커 노드)
    CONFIG_FILES = [
        "/var/lib/kubelet/config.yaml",
        "/etc/kubernetes/kubelet.conf"
    ]

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
            
            # 워커 노드 파일 권한은 노드에 직접 접근해야 확인 가능
            # 일반적으로는 DaemonSet이나 노드 접근이 필요하므로 WARN 처리
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                os_image = node_info.get("osImage", "unknown")
                
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Node",
                    "ObjectName": node_name,
                    "Namespace": "N/A",
                    "Reason": "워커 노드 설정 파일 권한을 자동으로 확인할 수 없음 (노드에 직접 접근 필요)",
                    "Evidence": {
                        "node": node_name,
                        "os_image": os_image,
                        "files_to_check": self.CONFIG_FILES
                    },
                    "Remediation": (
                        f"노드 {node_name}에 직접 접근하여 다음 파일들의 권한을 확인하세요:\n\n" +
                        "\n".join(f"- {f}" for f in self.CONFIG_FILES) +
                        "\n\n권장 설정:\n"
                        "- 소유자: root\n"
                        "- 소유 그룹: root\n"
                        "- 권한: 644 (rw-r--r--)\n\n"
                        "확인 명령:\n"
                        "ls -al /var/lib/kubelet/config.yaml\n"
                        "ls -al /etc/kubernetes/kubelet.conf\n\n"
                        "수정 명령:\n"
                        "sudo chown root:root <file>\n"
                        "sudo chmod 644 <file>"
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
