# 보안 점검 항목: Kubelet TLS 설정
# scanner/checks/kubelet_tls.py
from .base import Check
import subprocess, json, traceback

class KubeletTLSCheck(Check):
    id = "CHK-W-KUBELET-003"
    name = "SSL/TLS 활성화"
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

    def run(self, kubeconfig='', node_scanner_data=None):
        
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
                per_node = {}
                any_fail = False
                any_error = False

                for node in node_items:
                    node_name = node.get("metadata", {}).get("name", "unknown")
                    node_info = node.get("status", {}).get("nodeInfo", {})
                    kubelet_version = node_info.get("kubeletVersion", "unknown")

                    nd = ns_nodes.get(node_name) or {}
                    kubelet = nd.get("kubelet") or {}
                    present = kubelet.get("present") == "true"
                    has_cert = kubelet.get("has_tlsCertFile") == "true"
                    has_key = kubelet.get("has_tlsPrivateKeyFile") == "true"
                    server_bootstrap = kubelet.get("serverTLSBootstrap") == "true"

                    if not present:
                        status = "ERROR"
                        any_error = True
                        reason = (
                            f"[{node_name}] 노드에서 kubelet 설정 파일(/var/lib/kubelet/config.yaml)을 읽을 수 없습니다. "
                            "경로 없음 또는 node-scanner hostPath 마운트 확인 필요."
                        )
                    else:
                        if server_bootstrap or (has_cert and has_key):
                            status = "PASS"
                            reason = "Kubelet TLS 설정이 확인됨"
                        else:
                            status = "FAIL"
                            any_fail = True
                            reason = "Kubelet TLS 설정이 없거나 부적절함"

                    per_node[node_name] = {
                        "result": status,
                        "reason": reason,
                        "kubelet_version": kubelet_version,
                        "pod": nd.get("pod"),
                        "kubelet_summary": kubelet,
                        "error": nd.get("error"),
                    }

                overall = "ERROR" if any_error else ("FAIL" if any_fail else "PASS")
                node_names = ", ".join(sorted(per_node.keys()))
                error_nodes = [n for n, p in per_node.items() if p.get("result") == "ERROR"]
                reason_main = (
                    f"다음 노드에서 kubelet 설정 파일을 읽을 수 없음: {', '.join(error_nodes)}. "
                    "node-scanner DaemonSet 배포 여부 및 /var/lib/kubelet/config.yaml 경로를 확인하세요."
                ) if any_error else "노드별 kubelet TLS 설정 점검 결과"
                return [{
                    "CheckID": self.id,
                    "Result": overall,
                    "ObjectType": "Cluster",
                    "ObjectName": node_names or "ALL",
                    "Namespace": "N/A",
                    "Reason": reason_main,
                    "Evidence": {"per_node": per_node},
                    "Remediation": (
                        "1) node-scanner 배포: kubectl apply -f k8s/node-scanner-daemonset.yaml\n"
                        "2) 각 노드의 kubelet TLS 설정: serverTLSBootstrap: true 또는 --tls-cert-file / --tls-private-key-file\n"
                    ) if any_error else (
                        "각 노드의 kubelet TLS 설정을 활성화하세요.\n"
                        "예: serverTLSBootstrap: true 또는 --tls-cert-file / --tls-private-key-file\n"
                    )
                }]

            # fallback: ConfigMap 기반
            per_node = {}
            any_fail = False
            any_error = False
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                kubelet_version = node_info.get("kubeletVersion", "unknown")
                tls_check = self._check_kubelet_tls(node_name, kubeconfig)
                if tls_check.get("has_tls") is True:
                    status = "PASS"
                elif tls_check.get("has_tls") is False:
                    status = "FAIL"
                    any_fail = True
                else:
                    status = "ERROR"
                    any_error = True
                per_node[node_name] = {
                    "result": status,
                    "kubelet_version": kubelet_version,
                    "error": tls_check.get("error"),
                }
            overall = "ERROR" if any_error else ("FAIL" if any_fail else "PASS")
            node_names = ", ".join(sorted(per_node.keys()))
            reason_fallback = (
                "ConfigMap에서 kubelet TLS 설정을 확인할 수 없습니다. "
                "node-scanner DaemonSet을 배포하면 노드별 config를 직접 읽어 검사할 수 있습니다."
            ) if any_error else "kubelet TLS 설정 점검 결과(ConfigMap 기반)"
            return [{
                "CheckID": self.id,
                "Result": overall,
                "ObjectType": "Cluster",
                "ObjectName": node_names or "ALL",
                "Namespace": "N/A",
                "Reason": reason_fallback,
                "Evidence": {"per_node": per_node},
                "Remediation": "kubectl apply -f k8s/node-scanner-daemonset.yaml 로 node-scanner 배포 후 다시 스캔하세요."
            }]
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "kubectl get nodes 명령을 직접 실행하여 확인하세요"
            }]

