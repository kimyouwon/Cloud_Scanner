# 보안 점검 항목: Kubelet 인증 제어
# scanner/checks/kubelet_auth.py
from .base import Check
import subprocess, json, traceback, re

class KubeletAuthCheck(Check):
    id = "CHK-W-KUBELET-001"
    name = "Kubelet 인증 제어 검사"
    category = "Worker"
    severity = "Critical"
    points = 6
    risk_level = 9
    description = "Kubelet은 각 노드에서 실행되는 에이전트로 Pod에 대해 정의된 PodSpec(yaml 또는 Json 형태)에 따라 컨테이너를 실행하고 동작하도록 관리하는 역할을 한다. 따라서 Kubelet의 비인증 접근은 Pod와 컨테이너의 정보 노출, 리소스 수정 등에 대해 영향을 줄 수 있으므로 Kubelet 인증 후 접근할 수 있도록 해야 한다."
    recommended_setting = "비인증 접근이 차단된 경우\n- --anonymous-auth=false\n- --read-only-port=0 또는 미설정"
    verification_command = "$ cat [kubelet service 파일 경로] | grep 'anonymous-auth\\|read-only-port' | grep -v '#'\n$ cat [kubelet config 파일 경로]"

    # 일반적인 kubelet 설정 파일 경로
    KUBELET_SERVICE_PATHS = [
        "/usr/lib/systemd/system/kubelet.service",
        "/etc/systemd/system/kubelet.service",
        "/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf"
    ]
    
    KUBELET_CONFIG_PATHS = [
        "/var/lib/kubelet/config.yaml",
        "/etc/kubernetes/kubelet.conf"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _check_via_node_pod(self, node_name, file_paths, kubeconfig=''):
        """노드의 파드를 통해 파일 확인"""
        findings = {}
        try:
            # 노드의 파드 찾기 (kube-proxy 등)
            res = self._kubectl(["get", "pods", "-A", "-o", "json", "--field-selector", f"spec.nodeName={node_name}"], kubeconfig)
            if res.returncode != 0:
                return findings
            
            pods = json.loads(res.stdout)
            if not pods.get("items"):
                return findings
            
            # 첫 번째 파드 사용
            pod = pods["items"][0]
            pod_name = pod.get("metadata", {}).get("name")
            namespace = pod.get("metadata", {}).get("namespace")
            
            for file_path in file_paths:
                # cat 명령으로 파일 내용 확인
                cmd = ["exec", pod_name, "-n", namespace, "--", "cat", file_path]
                res = self._kubectl(cmd, kubeconfig)
                if res.returncode == 0:
                    findings[file_path] = res.stdout
        except Exception:
            pass
        
        return findings

    def _extract_flag_value(self, content, flag_name):
        """파일 내용에서 플래그 값 추출"""
        if not content:
            return None
        
        # --flag=value 형식
        pattern1 = rf'{re.escape(flag_name)}=([^\s\n]+)'
        match = re.search(pattern1, content)
        if match:
            return match.group(1).strip()
        
        # --flag value 형식
        pattern2 = rf'{re.escape(flag_name)}\s+([^\s\n]+)'
        match = re.search(pattern2, content)
        if match:
            return match.group(1).strip()
        
        return None

    def _check_kubelet_config_yaml(self, content):
        """YAML 형식의 kubelet config 파일 확인"""
        if not content:
            return {}
        
        try:
            import yaml
            config = yaml.safe_load(content)
            if not config:
                return {}
            
            result = {}
            # anonymousAuth 필드 확인
            if "authentication" in config:
                auth = config["authentication"]
                if "anonymous" in auth:
                    result["anonymous-auth"] = not auth["anonymous"].get("enabled", True)
            
            # readOnlyPort 필드 확인
            if "server" in config:
                server = config["server"]
                if "readOnlyPort" in server:
                    port = server["readOnlyPort"]
                    result["read-only-port"] = port == 0
                else:
                    result["read-only-port"] = True  # 기본값이 0이므로
            
            return result
        except Exception:
            return {}

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
                
                # 노드의 파드를 통해 파일 확인 시도
                all_files = self.KUBELET_SERVICE_PATHS + self.KUBELET_CONFIG_PATHS
                file_contents = self._check_via_node_pod(node_name, all_files, kubeconfig)
                
                issues = []
                evidence = {"node": node_name}
                
                # Service 파일 확인
                for service_path in self.KUBELET_SERVICE_PATHS:
                    if service_path in file_contents:
                        content = file_contents[service_path]
                        # 주석 제거
                        lines = [l for l in content.split('\n') if not l.strip().startswith('#')]
                        content_clean = '\n'.join(lines)
                        
                        # anonymous-auth 확인
                        anonymous_auth = self._extract_flag_value(content_clean, "--anonymous-auth")
                        if anonymous_auth and anonymous_auth.lower() != "false":
                            issues.append(f"{service_path}: anonymous-auth={anonymous_auth} (false여야 함)")
                            evidence[f"{service_path}_anonymous-auth"] = anonymous_auth
                        
                        # read-only-port 확인
                        read_only_port = self._extract_flag_value(content_clean, "--read-only-port")
                        if read_only_port and read_only_port != "0":
                            issues.append(f"{service_path}: read-only-port={read_only_port} (0이어야 함)")
                            evidence[f"{service_path}_read-only-port"] = read_only_port
                        elif read_only_port is None:
                            # 플래그가 없으면 기본값(10255)이 활성화됨
                            issues.append(f"{service_path}: read-only-port 플래그가 없음 (기본값 10255 활성화)")
                            evidence[f"{service_path}_read-only-port"] = "not_set"
                
                # Config 파일 확인 (YAML)
                for config_path in self.KUBELET_CONFIG_PATHS:
                    if config_path in file_contents:
                        content = file_contents[config_path]
                        config_check = self._check_kubelet_config_yaml(content)
                        
                        if "anonymous-auth" in config_check and not config_check["anonymous-auth"]:
                            issues.append(f"{config_path}: anonymous authentication이 활성화됨")
                            evidence[f"{config_path}_anonymous-auth"] = "enabled"
                        
                        if "read-only-port" in config_check and not config_check["read-only-port"]:
                            issues.append(f"{config_path}: read-only-port가 0이 아님")
                            evidence[f"{config_path}_read-only-port"] = "not_zero"
                
                if issues:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "FAIL",
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": "; ".join(issues),
                        "Evidence": evidence,
                        "Remediation": (
                            f"노드 {node_name}의 kubelet 설정을 수정하세요:\n\n"
                            "1. kubelet service 파일 수정:\n"
                            "   sudo vi /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf\n\n"
                            "2. 다음 플래그 추가/수정:\n"
                            "   --anonymous-auth=false\n"
                            "   --read-only-port=0\n\n"
                            "3. kubelet 재시작:\n"
                            "   sudo systemctl daemon-reload\n"
                            "   sudo systemctl restart kubelet\n\n"
                            "또는 kubelet config.yaml 파일에서:\n"
                            "   authentication:\n"
                            "     anonymous:\n"
                            "       enabled: false\n"
                            "   server:\n"
                            "     readOnlyPort: 0"
                        )
                    })
                else:
                    # 파일을 확인할 수 없었지만, 기본적으로 WARN
                    if not file_contents:
                        findings.append({
                            "CheckID": self.id,
                            "Result": "WARN",
                            "ObjectType": "Node",
                            "ObjectName": node_name,
                            "Namespace": "N/A",
                            "Reason": "kubelet 설정 파일을 확인할 수 없음 (노드에 직접 접근 필요)",
                            "Evidence": {"node": node_name},
                            "Remediation": (
                                f"노드 {node_name}에 직접 접근하여 다음 명령으로 확인하세요:\n\n"
                                "$ cat /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf | grep 'anonymous-auth\\|read-only-port' | grep -v '#'\n"
                                "$ cat /var/lib/kubelet/config.yaml\n\n"
                                "권장 설정:\n"
                                "- --anonymous-auth=false\n"
                                "- --read-only-port=0"
                            )
                        })
            
            if not findings:
                # 모든 노드가 적절히 설정됨
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": "모든 노드의 kubelet 인증 설정이 적절함",
                    "Evidence": {"checked_nodes": len(node_items)},
                    "Remediation": ""
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "노드에 직접 접근하여 kubelet 설정을 확인하세요"
            }]
        
        return findings

