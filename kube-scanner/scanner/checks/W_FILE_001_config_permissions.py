# 보안 점검 항목: Worker 노드 환경설정 파일 권한 설정
# scanner/checks/worker_config_file_permissions.py
from .base import Check
import subprocess, json, traceback, stat, os

class WorkerConfigFilePermissionsCheck(Check):
    id = "CHK-W-FILE-001"
    name = "Worker 노드 환경설정 파일 권한 설정 검사"
    category = "Worker"
    severity = "High"
    points = 4
    risk_level = 8
    description = "Kubernetes 설정 파일에 비인가자의 접근이 가능한 경우 Kubernetes 설정을 변경하여 침해 사고를 일으킬 가능성이 있다. 따라서 root 외 다른 사용자가 이 파일을 수정할 수 없도록 파일의 권한을 제한해야 한다."
    recommended_setting = "환경설정 파일의 소유자 및 소유 그룹이 root이고, 접근 권한이 644 이하로 설정된 경우"
    verification_command = "$ stat -c %a:%U:%G /etc/kubernetes/kubelet.conf\n$ stat -c %a:%U:%G /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf\n$ stat -c %a:%U:%G /var/lib/kubelet/config.yaml"

    # Worker 노드의 kubelet 설정 파일 (minikube 경로 포함)
    CONFIG_FILES = [
        "/etc/kubernetes/kubelet.conf",
        "/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf",
        "/var/lib/kubelet/config.yaml",
        # minikube 경로
        "/var/lib/minikube/kubelet.conf"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

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

    def _validate_file_permissions(self, file_info):
        """파일 권한이 요구사항을 만족하는지 확인"""
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
        
        if mode > 420:  # 644 = 420 (0o644)
            issues.append(f"권한이 644보다 큼 (현재: {oct(mode)} = {mode})")
        
        if mode & 0o002:  # other write
            issues.append("other에 쓰기 권한이 있음")
        
        if mode & 0o020:  # group write
            issues.append("group에 쓰기 권한이 있음")
        
        if issues:
            return {"valid": False, "reason": "; ".join(issues)}
        else:
            return {"valid": True, "reason": "권한 설정이 적절함"}

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
                missing_files = []
                
                for file_path in self.CONFIG_FILES:
                    file_info = self._check_file_permissions_via_pod(pod_name, namespace, file_path, kubeconfig)
                    
                    if not file_info or not file_info.get("exists"):
                        missing_files.append(file_path)
                        continue
                    
                    validation = self._validate_file_permissions(file_info)
                    
                    if not validation["valid"]:
                        failed_files.append({
                            "path": file_path,
                            "info": file_info,
                            "reason": validation["reason"]
                        })
                
                if failed_files:
                    for failed in failed_files:
                        findings.append({
                            "CheckID": self.id,
                            "Result": "FAIL",
                            "ObjectType": "File",
                            "ObjectName": f"{node_name}:{failed['path']}",
                            "Namespace": "N/A",
                            "Reason": f"파일 권한 설정이 부적절함: {failed['reason']}",
                            "Evidence": {
                                "node": node_name,
                                "path": failed["path"],
                                "owner": failed["info"].get("owner"),
                                "group": failed["info"].get("group"),
                                "mode": failed["info"].get("mode"),
                                "permissions": failed["info"].get("permissions")
                            },
                            "Remediation": (
                                f"노드 {node_name}의 파일 {failed['path']} 권한을 수정하세요:\n"
                                f"sudo chown root:root {failed['path']}\n"
                                f"sudo chmod 644 {failed['path']}\n\n"
                                "권장 설정:\n"
                                "- 소유자: root\n"
                                "- 소유 그룹: root\n"
                                "- 권한: 644 (rw-r--r--)"
                            )
                        })
                
                if missing_files:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "WARN",
                        "ObjectType": "File",
                        "ObjectName": f"{node_name}:Multiple",
                        "Namespace": "N/A",
                        "Reason": f"다음 파일들을 확인할 수 없음: {', '.join(missing_files)}",
                        "Evidence": {"node": node_name, "missing_files": missing_files},
                        "Remediation": (
                            f"노드 {node_name}에 직접 접근하여 다음 파일들의 권한을 확인하세요:\n" +
                            "\n".join(f"- {f}" for f in missing_files) +
                            "\n\n권장 설정:\n"
                            "- 소유자: root\n"
                            "- 소유 그룹: root\n"
                            "- 권한: 644 (rw-r--r--)\n\n"
                            "수정 명령:\n"
                            "sudo chown root:root <file>\n"
                            "sudo chmod 644 <file>"
                        )
                    })
            
            if not findings:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": "모든 노드의 환경설정 파일 권한이 적절함",
                    "Evidence": {"checked_nodes": len(node_items)},
                    "Remediation": ""
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "노드에 직접 접근하여 파일 권한을 확인하세요"
            }]
        
        return findings




