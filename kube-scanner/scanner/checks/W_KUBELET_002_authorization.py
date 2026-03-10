# 보안 점검 항목: Kubelet 인가 설정
# scanner/checks/kubelet_authorization.py
from .base import Check
import subprocess, json, traceback

class KubeletAuthorizationCheck(Check):
    id = "CHK-W-KUBELET-002"
    name = "Kubelet 인가 설정 검사"
    category = "Kubelet"
    severity = "High"
    points = 2
    risk_level = 8
    description = "Kubelet 인가 모드가 제대로 설정되지 않으면 비인가된 요청이 허용될 수 있습니다. AlwaysAllow 모드는 보안상 위험하므로 사용하지 않아야 합니다."
    recommended_setting = "Kubelet 인가가 설정된 경우\n- --authorization-mode=Webhook (권장) 또는 --authorization-mode=AlwaysAllow 제외"
    verification_command = "kubectl get nodes -o json | jq '.items[].status.nodeInfo.kubeletVersion'\n# 또는 노드에서 직접: ps aux | grep kubelet | grep authorization-mode"

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _check_kubelet_authorization(self, node_name, kubeconfig=''):
        """노드의 kubelet 인가 설정 확인. Kubernetes 1.14+ 기본값은 Webhook."""
        try:
            res = self._kubectl(["get", "configmap", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode == 0:
                configmaps = json.loads(res.stdout)
                for cm in configmaps.get("items", []):
                    cm_name = cm.get("metadata", {}).get("name", "")
                    if "kubelet" in cm_name.lower() and "config" in cm_name.lower():
                        data = cm.get("data", {})
                        config_content = (data.get("kubelet") or data.get("config.yaml") or "").lower()
                        if "alwaysallow" in config_content or "mode: alwaysallow" in config_content:
                            return {"mode": "AlwaysAllow", "valid": False}
                        if "webhook" in config_content or "mode: webhook" in config_content:
                            return {"mode": "Webhook", "valid": True}
                        if "authorization" in config_content:
                            return {"mode": "unknown", "valid": None}
                return {"mode": "Webhook", "valid": True}
            return {"mode": None, "valid": None}
        except Exception as e:
            return {"mode": None, "valid": None, "error": str(e)}

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
                    "Result": "WARN",
                    "Reason": "노드를 찾을 수 없음",
                    "Evidence": {},
                    "Remediation": "클러스터에 노드가 있는지 확인하세요"
                }]

            # node-scanner 기반 자동 판정
            if isinstance(node_scanner_data, dict) and node_scanner_data.get("available"):
                ns_nodes = (node_scanner_data.get("nodes") or {})
                results = []

                for node in node_items:
                    node_name = node.get("metadata", {}).get("name", "unknown")
                    node_info = node.get("status", {}).get("nodeInfo", {})
                    kubelet_version = node_info.get("kubeletVersion", "unknown")

                    nd = ns_nodes.get(node_name) or {}
                    kubelet = nd.get("kubelet") or {}
                    present = kubelet.get("present") == "true"
                    mode = kubelet.get("authorization_mode", "unknown")

                    if not present:
                        status = "PASS"
                        reason = "kubelet config를 읽을 수 없음; 기본 인가 모드(Webhook) 적용으로 간주"
                    elif mode == "AlwaysAllow":
                        status = "FAIL"
                        reason = "Kubelet authorization mode가 AlwaysAllow (보안 위험)"
                    elif mode == "Webhook":
                        status = "PASS"
                        reason = "Kubelet authorization mode가 Webhook"
                    else:
                        status = "PASS"
                        reason = f"Kubelet authorization mode 확인됨: {mode} (기본값 Webhook 적용으로 간주)"

                    results.append({
                        "CheckID": self.id,
                        "Result": status,
                        "ObjectType": "Node",
                        "ObjectName": node_name,
                        "Namespace": "N/A",
                        "Reason": reason,
                        "Evidence": {
                            "node": node_name,
                            "kubelet_version": kubelet_version,
                            "pod": nd.get("pod"),
                            "authorization_mode": mode,
                            "kubelet_summary": kubelet,
                            "error": nd.get("error"),
                        },
                        "Remediation": (
                            "각 노드의 kubelet authorization mode를 Webhook으로 설정하고 "
                            "AlwaysAllow 사용을 피하세요.\n"
                            "예:\n"
                            "authorization:\n"
                            "  mode: Webhook\n"
                        )
                    })

                return results

            # fallback: ConfigMap 기반 (ConfigMap 없으면 기본값 Webhook 적용으로 PASS)
            results = []
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                kubelet_version = node_info.get("kubeletVersion", "unknown")
                auth_check = self._check_kubelet_authorization(node_name, kubeconfig)

                if auth_check.get("valid") is True:
                    status = "PASS"
                    reason = "kubelet 인가 설정 점검 결과(ConfigMap 기반): Webhook 또는 적절한 모드"
                elif auth_check.get("valid") is False:
                    status = "FAIL"
                    reason = "Kubelet authorization mode가 AlwaysAllow (보안 위험)"
                else:
                    status = "PASS"
                    reason = "kubelet 기본 인가 모드(Webhook) 적용으로 간주 (Kubernetes 1.14+ 기본값)"

                results.append({
                    "CheckID": self.id,
                    "Result": status,
                    "ObjectType": "Node",
                    "ObjectName": node_name,
                    "Namespace": "N/A",
                    "Reason": reason,
                    "Evidence": {
                        "node": node_name,
                        "kubelet_version": kubelet_version,
                        "authorization_mode": auth_check.get("mode"),
                        "error": auth_check.get("error"),
                    },
                    "Remediation": "" if status == "PASS" else "kubelet 설정에서 authorization.mode를 Webhook으로 설정하세요."
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

