# 보안 점검 항목: Kubelet SSL/TLS 적용
# scanner/checks/kubelet_tls.py
from .base import Check
import subprocess, json, traceback, re

class KubeletTLSCheck(Check):
    id = "CHK-W-KUBELET-003"
    name = "Kubelet SSL/TLS 적용 검사"
    category = "Worker"
    severity = "High"
    points = 5
    risk_level = 7
    description = "API server, node 간 통신 시 민감한 데이터들이 평문으로 전송되면 스니핑과 같은 방법으로 민감한 데이터가 노출되므로 SSL/TLS 통신을 적용하여 송수신되는 데이터들을 보호하고 접근하는 대상에 대해 인증해야 한다. SSL/TLS 통신 적용 시 주기적으로 인증서를 변경하고 안전한 cipher suite를 사용해야 한다."
    recommended_setting = "kubelet SSL/TLS 통신을 위한 설정(인증서, 비밀키, 인증서 교환 주기, TLS 버전, cipher suites, hostname 변경 설정 비활성화)이 적용된 경우"
    verification_command = "$ cat [kubelet config 파일 경로]\nclientCAFile : [CA 인증서 파일 경로]\ntlsCertFile : [인증서 파일 경로]\ntlsPrivateKeyFile : [Private key 파일 경로]\nTLSCipherSuites :\n$ cat [kubelet service 파일 경로]를 확인하여 --hostname-override 설정이 존재하는지 확인(존재하지 않아야 함)"

    KUBELET_SERVICE_PATHS = [
        "/usr/lib/systemd/system/kubelet.service",
        "/etc/systemd/system/kubelet.service",
        "/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf"
    ]
    
    KUBELET_CONFIG_PATHS = [
        "/var/lib/kubelet/config.yaml",
        "/etc/kubernetes/kubelet.conf"
    ]

    WEAK_CIPHER_INDICATORS = ["rc4", "des", "3des", "null", "exp", "md5", "sha1", "tlsv1.0", "tlsv1.1"]

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
        
        pattern1 = rf'{re.escape(flag_name)}=([^\s\n]+)'
        match = re.search(pattern1, content)
        if match:
            return match.group(1).strip()
        
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
            
            # clientCAFile 확인
            if "authentication" in config:
                auth = config["authentication"]
                if "x509" in auth and "clientCAFile" in auth["x509"]:
                    result["clientCAFile"] = auth["x509"]["clientCAFile"]
                else:
                    result["clientCAFile"] = None
            
            # tlsCertFile, tlsPrivateKeyFile 확인
            if "server" in config:
                server = config["server"]
                if "tlsCertFile" in server:
                    result["tlsCertFile"] = server["tlsCertFile"]
                else:
                    result["tlsCertFile"] = None
                
                if "tlsPrivateKeyFile" in server:
                    result["tlsPrivateKeyFile"] = server["tlsPrivateKeyFile"]
                else:
                    result["tlsPrivateKeyFile"] = None
                
                # TLSCipherSuites 확인
                if "tlsCipherSuites" in server:
                    result["tlsCipherSuites"] = server["tlsCipherSuites"]
                else:
                    result["tlsCipherSuites"] = None
            
            return result
        except Exception:
            return {}

    def _contains_weak_cipher(self, cipher_string):
        """약한 cipher suite 확인"""
        if not cipher_string:
            return False
        s = str(cipher_string).lower()
        for w in self.WEAK_CIPHER_INDICATORS:
            if w in s:
                return True
        return False

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
                
                # Service 파일 확인 - hostname-override 확인
                for service_path in self.KUBELET_SERVICE_PATHS:
                    if service_path in file_contents:
                        content = file_contents[service_path]
                        lines = [l for l in content.split('\n') if not l.strip().startswith('#')]
                        content_clean = '\n'.join(lines)
                        
                        hostname_override = self._extract_flag_value(content_clean, "--hostname-override")
                        if hostname_override:
                            issues.append(f"{service_path}: --hostname-override={hostname_override} (설정이 없어야 함)")
                            evidence[f"{service_path}_hostname-override"] = hostname_override
                
                # Config 파일 확인 (YAML)
                for config_path in self.KUBELET_CONFIG_PATHS:
                    if config_path in file_contents:
                        content = file_contents[config_path]
                        config_check = self._check_kubelet_config_yaml(content)
                        
                        # clientCAFile 확인
                        if "clientCAFile" in config_check:
                            if config_check["clientCAFile"] is None:
                                issues.append(f"{config_path}: clientCAFile이 설정되지 않음")
                                evidence[f"{config_path}_clientCAFile"] = "not_set"
                            else:
                                evidence[f"{config_path}_clientCAFile"] = config_check["clientCAFile"]
                        
                        # tlsCertFile 확인
                        if "tlsCertFile" in config_check:
                            if config_check.get("tlsCertFile") is None:
                                issues.append(f"{config_path}: tlsCertFile이 설정되지 않음")
                                evidence[f"{config_path}_tlsCertFile"] = "not_set"
                            else:
                                evidence[f"{config_path}_tlsCertFile"] = config_check["tlsCertFile"]
                        
                        # tlsPrivateKeyFile 확인
                        if "tlsPrivateKeyFile" in config_check:
                            if config_check["tlsPrivateKeyFile"] is None:
                                issues.append(f"{config_path}: tlsPrivateKeyFile이 설정되지 않음")
                                evidence[f"{config_path}_tlsPrivateKeyFile"] = "not_set"
                            else:
                                evidence[f"{config_path}_tlsPrivateKeyFile"] = config_check["tlsPrivateKeyFile"]
                        
                        # TLSCipherSuites 확인
                        if "tlsCipherSuites" in config_check:
                            cipher_suites = config_check["tlsCipherSuites"]
                            if cipher_suites is None:
                                issues.append(f"{config_path}: TLSCipherSuites가 설정되지 않음")
                                evidence[f"{config_path}_tlsCipherSuites"] = "not_set"
                            elif self._contains_weak_cipher(str(cipher_suites)):
                                issues.append(f"{config_path}: 약한 cipher suite 사용: {cipher_suites}")
                                evidence[f"{config_path}_tlsCipherSuites"] = cipher_suites
                            else:
                                evidence[f"{config_path}_tlsCipherSuites"] = cipher_suites
                
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
                            f"노드 {node_name}의 kubelet TLS 설정을 수정하세요:\n\n"
                            "1. kubelet config.yaml 파일 수정:\n"
                            "   sudo vi /var/lib/kubelet/config.yaml\n\n"
                            "2. 다음 설정 추가:\n"
                            "   authentication:\n"
                            "     x509:\n"
                            "       clientCAFile: /etc/kubernetes/pki/ca.crt\n"
                            "   server:\n"
                            "     tlsCertFile: /var/lib/kubelet/pki/kubelet.crt\n"
                            "     tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key\n"
                            "     tlsCipherSuites:\n"
                            "       - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n"
                            "       - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n"
                            "       - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305\n"
                            "       - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
                            "       - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305\n"
                            "       - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n\n"
                            "3. --hostname-override 플래그 제거 (service 파일에서)\n\n"
                            "4. kubelet 재시작:\n"
                            "   sudo systemctl daemon-reload\n"
                            "   sudo systemctl restart kubelet"
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
                                f"노드 {node_name}에 직접 접근하여 kubelet TLS 설정을 확인하세요:\n\n"
                                "$ cat /var/lib/kubelet/config.yaml\n"
                                "$ cat /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf | grep hostname-override\n\n"
                                "권장 설정:\n"
                                "- clientCAFile 설정\n"
                                "- tlsCertFile, tlsPrivateKeyFile 설정\n"
                                "- TLSCipherSuites 설정 (약한 cipher 제외)\n"
                                "- --hostname-override 플래그 제거"
                            )
                        })
            
            if not findings:
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": "모든 노드의 kubelet TLS 설정이 적절함",
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

