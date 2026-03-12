# 보안 점검 항목: 워커 노드 인증서 파일 권한 설정
# scanner/checks/worker_certificate_file_permissions.py
from .base import Check
import subprocess, json, traceback

class WorkerCertificateFilePermissionsCheck(Check):
    id = "CHK-W-FILE-002"
    name = "워커 노드 인증서 파일 권한"
    category = "File"
    severity = "High"
    points = 2
    risk_level = 7
    description = "워커 노드의 인증서 파일 접근 권한이 과도하게 설정될 경우, SSL 구성을 통한 네트워크상 데이터 보호 및 사용자 인증을 위해 사용되는 인증서가 비인가자에 의해 유출될 위험이 존재합니다."
    recommended_setting = "파일의 소유자 및 소유 그룹이 root이고, 인증서 파일의 접근 권한은 644, 키 파일의 접근 권한은 600 이하로 설정된 경우"
    verification_command = "ls -al /var/lib/kubelet/pki/*.crt\nls -al /var/lib/kubelet/pki/*.key"

    # 확인할 디렉터리 및 파일 패턴 (워커 노드)
    CERT_DIRECTORIES = [
        "/var/lib/kubelet/pki"
    ]
    
    # 인증서 파일 확장자 (644 이하)
    CERT_EXTENSIONS = [".crt", ".pem", ".cert"]
    
    # 키 파일 확장자 (600 이하)
    KEY_EXTENSIONS = [".key"]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def run(self, kubeconfig='', node_scanner_data=None):
        """
        node-scanner DaemonSet 로그가 있으면 /var/lib/kubelet/pki 내 인증서/키 권한을 노드별로 자동 판정합니다.
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

            if isinstance(node_scanner_data, dict) and node_scanner_data.get("available"):
                ns_nodes = (node_scanner_data.get("nodes") or {})
                results = []

                def is_cert(path: str) -> bool:
                    p = path.lower()
                    return any(p.endswith(ext) for ext in self.CERT_EXTENSIONS)

                def is_key(path: str) -> bool:
                    return path.lower().endswith(".key")

                def validate_file(path: str, fi: dict):
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

                    max_mode = 644 if is_cert(path) else (600 if is_key(path) else 644)
                    if isinstance(mode, int) and mode > max_mode:
                        issues.append(f"mode={mode} (max {max_mode})")
                    if issues:
                        return False, "; ".join(issues)
                    if mode is None:
                        return None, "mode 확인 불가"
                    return True, "OK"

                for node in node_items:
                    node_name = node.get("metadata", {}).get("name", "unknown")
                    node_info = node.get("status", {}).get("nodeInfo", {})
                    os_image = node_info.get("osImage", "unknown")

                    nd = ns_nodes.get(node_name) or {}
                    files = nd.get("files") or {}
                    pki_files = {p: fi for p, fi in files.items() if p.startswith("/var/lib/kubelet/pki/")}

                    if not pki_files:
                        status = "ERROR"
                        reason = (
                            f"[{node_name}] 노드에 /var/lib/kubelet/pki 디렉터리(또는 파일)가 없거나 node-scanner가 읽지 못했습니다. "
                            "Kubelet이 해당 경로를 사용하는지, node-scanner hostPath 마운트를 확인하세요."
                        )
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
                                "files": {},
                                "error": nd.get("error"),
                            },
                            "Remediation": (
                                "노드에서 /var/lib/kubelet/pki 존재 여부 확인. "
                                "없으면 kubelet 인증서 경로가 다른지 확인. node-scanner 배포: kubectl apply -f k8s/node-scanner-daemonset.yaml\n"
                            )
                        })
                        continue

                    bad = []
                    warns = []
                    checked = {}
                    for path, fi in sorted(pki_files.items()):
                        ok, msg = validate_file(path, fi)
                        checked[path] = fi
                        if ok is False:
                            bad.append(f"{path}({msg})")
                        elif ok is None:
                            warns.append(f"{path}({msg})")

                    if bad:
                        status = "FAIL"
                        reason = "인증서/키 파일 권한이 부적절함: " + ", ".join(bad[:10]) + ("..." if len(bad) > 10 else "")
                    elif warns:
                        status = "ERROR"
                        reason = (
                            f"[{node_name}] 다음 인증서/키 파일이 없거나 권한 정보를 읽을 수 없음: "
                            + ", ".join(warns[:10]) + ("..." if len(warns) > 10 else "") + ". "
                            "파일 존재 여부 및 node-scanner 로그 수집 상태를 확인하세요."
                        )
                    else:
                        status = "PASS"
                        reason = "인증서/키 파일 권한이 권장값으로 설정됨"

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
                            "checked_count": len(checked),
                            "files": checked,
                            "error": nd.get("error"),
                        },
                        "Remediation": (
                            "각 인증서/키 파일의 소유자/그룹을 root로 설정하고,\n"
                            "인증서(.crt/.pem 등)는 mode <= 644,\n"
                            "키(.key)는 mode <= 600 으로 설정하세요.\n"
                        )
                    })

                return results

            # fallback – node-scanner 없음
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
                        f"[{node_name}] node-scanner DaemonSet이 없거나 로그를 수집하지 못해 인증서/키 파일 권한을 확인할 수 없습니다. "
                        "DaemonSet 배포 후 재검사하세요."
                    ),
                    "Evidence": {
                        "node": node_name,
                        "os_image": os_image,
                        "directories_to_check": self.CERT_DIRECTORIES,
                        "node_scanner_error": (node_scanner_data or {}).get("error") if isinstance(node_scanner_data, dict) else None
                    },
                    "Remediation": (
                        "1) node-scanner 배포: kubectl apply -f k8s/node-scanner-daemonset.yaml\n"
                        "2) 노드에서 인증서/키 권한 확인: ls -al /var/lib/kubelet/pki ; chown root:root ; chmod 644(.crt) 600(.key)\n"
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

