# 보안 점검 항목: Worker 노드 인증서 파일 권한 설정
# scanner/checks/worker_certificate_file_permissions.py
from .base import Check
import subprocess, json, traceback, stat, os, re

class WorkerCertificateFilePermissionsCheck(Check):
    id = "CHK-W-FILE-002"
    name = "Worker 노드 인증서 파일 권한 설정 검사"
    category = "Worker"
    severity = "High"
    points = 4
    risk_level = 8
    description = "SSL/TLS 통신 시 사용자 인증을 위해 사용되는 인증서가 root 외 다른 사용자가 인증서 파일에 접근할 수 없도록 인증서 파일의 권한을 제한하여 인증서가 변조되지 않도록 해야 한다."
    recommended_setting = "인증서 파일의 소유자 및 소유 그룹이 root이고, 접근 권한이 644 이하로 설정된 경우"
    verification_command = "$ ls -al [인증서를 생성한 위치]"

    # Worker 노드의 kubelet 인증서 디렉터리 (minikube 경로 포함)
    CERT_DIRECTORIES = [
        "/var/lib/kubelet/pki",
        "/etc/kubernetes/pki",
        # minikube 경로
        "/var/lib/minikube/certs"
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

    def _find_certificate_files_via_pod(self, pod_name, namespace, directory, kubeconfig=''):
        """파드를 통해 인증서 및 키 파일 찾기"""
        files = []
        try:
            find_cmd = f"find {directory} -type f \\( -name '*.crt' -o -name '*.key' -o -name '*.pem' -o -name '*.cert' \\) 2>/dev/null"
            cmd = ["exec", pod_name, "-n", namespace, "--", "sh", "-c", find_cmd]
            res = self._kubectl(cmd, kubeconfig)
            
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().split('\n'):
                    if line.strip():
                        files.append(line.strip())
        except Exception:
            pass
        
        return files

    def _check_file_permissions_via_pod(self, pod_name, namespace, file_path, kubeconfig=''):
        """파드를 통해 파일 권한 확인"""
        try:
            cmd = ["exec", pod_name, "-n", namespace, "--", "ls", "-ld", file_path]
            res = self._kubectl(cmd, kubeconfig)
            
            if res.returncode != 0:
                return None
            
            output = res.stdout.strip()
            if not output:
                return None
            
            parts = output.split()
            if len(parts) < 9:
                return None
            
            permissions = parts[0]
            owner = parts[2]
            group = parts[3]
            
            # 권한을 숫자로 변환
            mode_str = permissions[1:]
            mode = 0
            if len(mode_str) >= 9:
                if mode_str[0] == 'r': mode += 400
                if mode_str[1] == 'w': mode += 200
                if mode_str[2] == 'x': mode += 100
                if mode_str[3] == 'r': mode += 40
                if mode_str[4] == 'w': mode += 20
                if mode_str[5] == 'x': mode += 10
                if mode_str[6] == 'r': mode += 4
                if mode_str[7] == 'w': mode += 2
                if mode_str[8] == 'x': mode += 1
            
            return {
                "path": file_path,
                "permissions": permissions,
                "mode": mode,
                "owner": owner,
                "group": group,
                "exists": True
            }
        except Exception as e:
            return {"path": file_path, "exists": False, "error": str(e)}

    def _validate_certificate_file_permissions(self, file_info, is_key_file=False):
        """인증서/키 파일 권한 검증"""
        if not file_info.get("exists"):
            return {"valid": False, "reason": "파일이 존재하지 않음"}
        
        owner = file_info.get("owner", "")
        group = file_info.get("group", "")
        mode = file_info.get("mode", 0)
        
        issues = []
        
        if owner != "root":
            issues.append(f"소유자가 root가 아님 (현재: {owner})")
        
        if group != "root":
            issues.append(f"소유 그룹이 root가 아님 (현재: {group})")
        
        if is_key_file:
            # 키 파일은 600 이하 (rw-------)
            if mode > 384:  # 600 = 384 (0o600)
                issues.append(f"키 파일 권한이 600보다 큼 (현재: {oct(mode)} = {mode})")
            if mode & 0o077:  # group 또는 other 권한
                issues.append("키 파일에 group 또는 other 권한이 있음")
        else:
            # 인증서 파일은 644 이하 (rw-r--r--)
            if mode > 420:  # 644 = 420 (0o644)
                issues.append(f"인증서 파일 권한이 644보다 큼 (현재: {oct(mode)} = {mode})")
            if mode & 0o002:  # other write
                issues.append("인증서 파일에 other 쓰기 권한이 있음")
            if mode & 0o020:  # group write
                issues.append("인증서 파일에 group 쓰기 권한이 있음")
        
        if issues:
            return {"valid": False, "reason": "; ".join(issues)}
        else:
            return {"valid": True, "reason": "권한 설정이 적절함"}

    def _is_key_file(self, file_path):
        """키 파일인지 확인"""
        return any(file_path.endswith(ext) for ext in self.KEY_EXTENSIONS)

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
            
            # 각 노드별로 확인
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                
                # 노드의 파드 찾기
                res = self._kubectl(["get", "pods", "-A", "-o", "json", "--field-selector", f"spec.nodeName={node_name}"], kubeconfig)
                if res.returncode != 0:
                    continue
                
                pods = json.loads(res.stdout)
                if not pods.get("items"):
                    continue
                
                pod = pods["items"][0]
                pod_name = pod.get("metadata", {}).get("name")
                namespace = pod.get("metadata", {}).get("namespace")
                
                failed_files = []
                
                # 각 디렉터리에서 인증서 파일 찾기
                for directory in self.CERT_DIRECTORIES:
                    cert_files = self._find_certificate_files_via_pod(pod_name, namespace, directory, kubeconfig)
                    
                    for file_path in cert_files:
                        file_info = self._check_file_permissions_via_pod(pod_name, namespace, file_path, kubeconfig)
                        
                        if not file_info or not file_info.get("exists"):
                            continue
                        
                        is_key = self._is_key_file(file_path)
                        validation = self._validate_certificate_file_permissions(file_info, is_key)
                        
                        if not validation["valid"]:
                            failed_files.append({
                                "path": file_path,
                                "info": file_info,
                                "reason": validation["reason"],
                                "is_key": is_key
                            })
                
                if failed_files:
                    for failed in failed_files:
                        file_type = "키 파일" if failed["is_key"] else "인증서 파일"
                        recommended_mode = "600" if failed["is_key"] else "644"
                        
                        findings.append({
                            "CheckID": self.id,
                            "Result": "FAIL",
                            "ObjectType": "File",
                            "ObjectName": f"{node_name}:{failed['path']}",
                            "Namespace": "N/A",
                            "Reason": f"{file_type} 권한 설정이 부적절함: {failed['reason']}",
                            "Evidence": {
                                "node": node_name,
                                "path": failed["path"],
                                "file_type": file_type,
                                "owner": failed["info"].get("owner"),
                                "group": failed["info"].get("group"),
                                "mode": failed["info"].get("mode"),
                                "permissions": failed["info"].get("permissions")
                            },
                            "Remediation": (
                                f"노드 {node_name}의 {file_type} {failed['path']} 권한을 수정하세요:\n"
                                f"sudo chown root:root {failed['path']}\n"
                                f"sudo chmod {recommended_mode} {failed['path']}\n\n"
                                f"권장 설정 ({file_type}):\n"
                                "- 소유자: root\n"
                                "- 소유 그룹: root\n"
                                f"- 권한: {recommended_mode} ({'rw-------' if failed['is_key'] else 'rw-r--r--'})"
                            )
                        })
            
            if not findings:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": "모든 노드의 인증서 파일 권한이 적절함",
                    "Evidence": {"checked_nodes": len(node_items)},
                    "Remediation": ""
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "노드에 직접 접근하여 인증서 파일 권한을 확인하세요"
            }]
        
        return findings




