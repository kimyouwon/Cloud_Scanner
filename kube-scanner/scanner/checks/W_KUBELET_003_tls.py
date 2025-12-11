# 보안 점검 항목: Kubelet TLS 설정
# scanner/checks/kubelet_tls.py
from .base import Check
import subprocess, json, traceback

class KubeletTLSCheck(Check):
    id = "CHK-W-KUBELET-003"
    name = "Kubelet TLS 설정 검사"
    category = "Kubelet"
    severity = "High"
    points = 2
    risk_level = 8
    description = "Kubelet과 API Server 간 통신은 TLS로 암호화되어야 합니다. TLS가 설정되지 않으면 네트워크 스니핑 공격에 취약할 수 있습니다."
    recommended_setting = "Kubelet TLS가 설정된 경우\n- --tls-cert-file 설정\n- --tls-private-key-file 설정"
    verification_command = "kubectl get nodes -o json | jq '.items[].status.nodeInfo.kubeletVersion'\n# 또는 노드에서 직접: ps aux | grep kubelet | grep -E 'tls-cert-file|tls-private-key-file'"

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _check_kubelet_tls(self, node_name, kubeconfig=''):
        """노드의 kubelet TLS 설정 확인"""
        try:
            # kubelet 설정은 보통 ConfigMap으로 관리됨
            res = self._kubectl(["get", "configmap", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode == 0:
                configmaps = json.loads(res.stdout)
                for cm in configmaps.get("items", []):
                    cm_name = cm.get("metadata", {}).get("name", "")
                    if "kubelet" in cm_name.lower() and "config" in cm_name.lower():
                        data = cm.get("data", {})
                        config_content = data.get("kubelet", data.get("config.yaml", ""))
                        if "tlsCertFile" in config_content or "tlsPrivateKeyFile" in config_content:
                            return {"has_tls": True}
            
            return {"has_tls": None}
        except Exception as e:
            return {"has_tls": None, "error": str(e)}

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
            
            # 각 노드의 kubelet TLS 설정 확인
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                kubelet_version = node_info.get("kubeletVersion", "unknown")
                
                tls_check = self._check_kubelet_tls(node_name, kubeconfig)
                
                if tls_check.get("has_tls") is True:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "PASS",
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": "Kubelet TLS 설정이 확인됨",
                        "Evidence": {
                            "node": node_name,
                            "kubelet_version": kubelet_version
                        },
                        "Remediation": ""
                    })
                elif tls_check.get("has_tls") is False:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "FAIL",
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": "Kubelet TLS 설정이 없거나 부적절함",
                        "Evidence": {
                            "node": node_name,
                            "kubelet_version": kubelet_version
                        },
                        "Remediation": (
                            f"노드 {node_name}의 kubelet 설정에 TLS 관련 플래그를 추가하세요.\n\n"
                            "kubelet 설정 파일(/var/lib/kubelet/config.yaml)에 다음을 추가:\n"
                            "serverTLSBootstrap: true\n\n"
                            "또는 kubelet 서비스 파일에 다음 플래그 추가:\n"
                            "--tls-cert-file=/var/lib/kubelet/pki/kubelet.crt\n"
                            "--tls-private-key-file=/var/lib/kubelet/pki/kubelet.key"
                        )
                    })
                else:
                    # 확인 불가
                    findings.append({
                        "CheckID": self.id,
                        "Result": "WARN",
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": "Kubelet TLS 설정을 자동으로 확인할 수 없음 (노드에 직접 접근 필요)",
                        "Evidence": {
                            "node": node_name,
                            "kubelet_version": kubelet_version,
                            "error": tls_check.get("error", "설정 확인 불가")
                        },
                        "Remediation": (
                            f"노드 {node_name}에 직접 접근하여 kubelet TLS 설정을 확인하세요:\n\n"
                            "1. kubelet 설정 파일 확인:\n"
                            "   cat /var/lib/kubelet/config.yaml | grep -E 'tls|TLS'\n\n"
                            "2. kubelet 서비스 파일 확인:\n"
                            "   cat /etc/systemd/system/kubelet.service.d/10-kubeadm.conf | grep -E 'tls-cert-file|tls-private-key-file'\n\n"
                            "권장 설정:\n"
                            "- --tls-cert-file=/var/lib/kubelet/pki/kubelet.crt\n"
                            "- --tls-private-key-file=/var/lib/kubelet/pki/kubelet.key"
                        )
                    })
            
            if not findings:
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "Reason": "노드 정보를 확인할 수 없음",
                    "Evidence": {},
                    "Remediation": "kubectl get nodes 명령으로 노드 상태 확인"
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
