# 보안 점검 항목: Kubelet 권한 제어
# scanner/checks/kubelet_authorization.py
from .base import Check
import subprocess, json, traceback, re

class KubeletAuthorizationCheck(Check):
    id = "CHK-W-KUBELET-002"
    name = "Kubelet 권한 제어 검사"
    category = "Worker"
    severity = "High"
    points = 4
    risk_level = 8
    description = "Kubelet은 기본적으로 API server 요청을 권한 인증 없이 모두 허용하고 있어 설정 변경을 통해 권한 인증 후 API server 요청을 처리하도록 해야 한다."
    recommended_setting = "API server 권한이 AlwaysAllow 값으로 설정되지 않은 경우\n- --authorization-mode=Webhook 또는 --authorization-mode=AlwaysDeny"
    verification_command = "$ cat [kubelet service 파일 경로] | grep 'authorization-mode' | grep -v '#'\n$ cat [kubelet config 파일 경로]"

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
            res = self._kubectl(["get", "pods", "-A", "-o", "json", "--field-selector", f"spec.nodeName={node_name}"], kubeconfig)
            if res.returncode != 0:
                return findings
            
            pods = json.loads(res.stdout)
            if not pods.get("items"):
                return findings
            
            pod = pods["items"][0]
            pod_name = pod.get("metadata", {}).get("name")
            namespace = pod.get("metadata", {}).get("namespace")
            
            for file_path in file_paths:
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
            # authorization 필드 확인
            if "authorization" in config:
                authz = config["authorization"]
                if "mode" in authz:
                    mode = authz["mode"]
                    result["authorization-mode"] = mode
                    result["is-safe"] = mode.lower() not in ["alwaysallow", "always-allow"]
                else:
                    result["authorization-mode"] = "AlwaysAllow"  # 기본값
                    result["is-safe"] = False
            
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
                
                all_files = self.KUBELET_SERVICE_PATHS + self.KUBELET_CONFIG_PATHS
                file_contents = self._check_via_node_pod(node_name, all_files, kubeconfig)
                
                issues = []
                evidence = {"node": node_name}
                
                # Service 파일 확인
                for service_path in self.KUBELET_SERVICE_PATHS:
                    if service_path in file_contents:
                        content = file_contents[service_path]
                        lines = [l for l in content.split('\n') if not l.strip().startswith('#')]
                        content_clean = '\n'.join(lines)
                        
                        authz_mode = self._extract_flag_value(content_clean, "--authorization-mode")
                        if authz_mode:
                            evidence[f"{service_path}_authorization-mode"] = authz_mode
                            if authz_mode.lower() in ["alwaysallow", "always-allow"]:
                                issues.append(f"{service_path}: authorization-mode={authz_mode} (AlwaysAllow는 위험함)")
                        else:
                            # 플래그가 없으면 기본값(AlwaysAllow) 사용
                            issues.append(f"{service_path}: authorization-mode 플래그가 없음 (기본값 AlwaysAllow 사용)")
                            evidence[f"{service_path}_authorization-mode"] = "not_set_defaults_to_AlwaysAllow"
                
                # Config 파일 확인 (YAML)
                for config_path in self.KUBELET_CONFIG_PATHS:
                    if config_path in file_contents:
                        content = file_contents[config_path]
                        config_check = self._check_kubelet_config_yaml(content)
                        
                        if "authorization-mode" in config_check:
                            mode = config_check["authorization-mode"]
                            evidence[f"{config_path}_authorization-mode"] = mode
                            if not config_check.get("is-safe", True):
                                issues.append(f"{config_path}: authorization mode가 {mode} (AlwaysAllow는 위험함)")
                
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
                            f"노드 {node_name}의 kubelet 권한 설정을 수정하세요:\n\n"
                            "1. kubelet service 파일 수정:\n"
                            "   sudo vi /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf\n\n"
                            "2. 다음 플래그 추가/수정:\n"
                            "   --authorization-mode=Webhook\n\n"
                            "또는\n"
                            "   --authorization-mode=AlwaysDeny\n\n"
                            "3. kubelet 재시작:\n"
                            "   sudo systemctl daemon-reload\n"
                            "   sudo systemctl restart kubelet\n\n"
                            "또는 kubelet config.yaml 파일에서:\n"
                            "   authorization:\n"
                            "     mode: Webhook"
                        )
                    })
                else:
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
                                "$ cat /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf | grep 'authorization-mode' | grep -v '#'\n"
                                "$ cat /var/lib/kubelet/config.yaml\n\n"
                                "권장 설정:\n"
                                "- --authorization-mode=Webhook 또는 --authorization-mode=AlwaysDeny"
                            )
                        })
            
            if not findings:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": "모든 노드의 kubelet 권한 설정이 적절함",
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




