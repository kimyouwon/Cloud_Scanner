# 보안 점검 항목: 워커 노드 환경설정 파일 권한 설정
# scanner/checks/worker_config_file_permissions.py
from .base import Check
import subprocess, json, traceback

class WorkerConfigFilePermissionsCheck(Check):
    id = "CHK-W-FILE-001"
    name = "(워커 노드) 설정 파일 권한"
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

    def run(self, kubeconfig='', node_scanner_data=None):
        """
        node-scanner DaemonSet 로그가 있으면 노드별 파일 권한을 자동 판정합니다.
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
                    "Result": "ERROR",
                    "Reason": "노드가 없어 검사할 수 없음",
                    "Evidence": {},
                    "Remediation": "클러스터에 노드가 있는지 확인하세요"
                }]

            # node-scanner 기반 자동 판정
            if isinstance(node_scanner_data, dict) and node_scanner_data.get("available"):
                ns_nodes = (node_scanner_data.get("nodes") or {})
                results = []

                def file_ok(fi):
                    # 권장: owner/group root, mode <= 644
                    if not fi or fi.get("missing"):
                        return None, "파일이 없거나 확인 불가"
                    owner = fi.get("owner")
                    group = fi.get("group")
                    mode = fi.get("mode")
                    issues = []
                    if owner and owner != "root":
                        issues.append(f"owner={owner}")
                    if group and group != "root":
                        issues.append(f"group={group}")
                    if isinstance(mode, int) and mode > 644:
                        issues.append(f"mode={mode}")
                    if issues:
                        return False, "; ".join(issues)
                    # mode를 못 읽었으면(=None) WARN으로
                    if mode is None:
                        return None, "mode 확인 불가"
                    return True, "OK"

                for node in node_items:
                    node_name = node.get("metadata", {}).get("name", "unknown")
                    node_info = node.get("status", {}).get("nodeInfo", {})
                    os_image = node_info.get("osImage", "unknown")

                    nd = ns_nodes.get(node_name) or {}
                    files = nd.get("files") or {}
                    node_issues = []
                    node_warns = []
                    node_files = {}

                    for path in self.CONFIG_FILES:
                        fi = files.get(path)
                        ok, msg = file_ok(fi)
                        node_files[path] = fi
                        if ok is False:
                            node_issues.append(f"{path}({msg})")
                        elif ok is None:
                            node_warns.append(f"{path}({msg})")

                    if node_issues:
                        status = "FAIL"
                        reason = "워커 노드 설정 파일 권한이 부적절함: " + ", ".join(node_issues)
                    elif node_warns:
                        status = "ERROR"
                        reason = (
                            f"[{node_name}] 노드에서 다음 파일이 없거나 node-scanner가 권한 정보를 읽지 못함: "
                            + ", ".join(node_warns) + ". hostPath 마운트 경로(/etc/kubernetes, /var/lib/kubelet)를 확인하세요."
                        )
                    else:
                        status = "PASS"
                        reason = "워커 노드 설정 파일 권한이 권장값으로 설정됨"

                    results.append({
                        "CheckID": self.id,
                        "Result": status,
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": reason,
                        "Evidence": {
                            "node": node_name,
                            "os_image": os_image,
                            "pod": nd.get("pod"),
                            "files": node_files,
                            "error": nd.get("error"),
                        },
                        "Remediation": (
                            "다음 파일의 소유자/그룹을 root로, 권한을 644 이하로 설정하세요:\n"
                            "- /var/lib/kubelet/config.yaml\n"
                            "- /etc/kubernetes/kubelet.conf\n"
                        )
                    })

                return results

            # fallback: node-scanner 없음 – 노드별로 직접 확인 안내
            results = []
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                os_image = node_info.get("osImage", "unknown")
                results.append({
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "ObjectType": "Node",
                    "ObjectName": node_name,
                    "Namespace": "N/A",
                    "Reason": (
                        f"[{node_name}] node-scanner DaemonSet이 없거나 로그를 수집하지 못해 설정 파일 권한을 확인할 수 없습니다. "
                        "DaemonSet 배포 후 재검사하세요."
                    ),
                    "Evidence": {
                        "node": node_name,
                        "os_image": os_image,
                        "files_to_check": self.CONFIG_FILES,
                        "node_scanner_error": (node_scanner_data or {}).get("error") if isinstance(node_scanner_data, dict) else None
                    },
                    "Remediation": (
                        "1) node-scanner 배포: kubectl apply -f k8s/node-scanner-daemonset.yaml\n"
                        "2) 노드에서 파일 권한 확인/수정: ls -al /var/lib/kubelet/config.yaml /etc/kubernetes/kubelet.conf ; chown root:root ; chmod 644\n"
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

