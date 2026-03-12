# 보안 점검 항목: Kubelet 인가 설정
# scanner/checks/kubelet_authorization.py
from .base import Check
import subprocess, json, traceback

class KubeletAuthorizationCheck(Check):
    id = "CHK-W-KUBELET-002"
    name = "인가 제어"
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
                    "Result": "ERROR",
                    "Reason": "노드가 없어 검사할 수 없음",
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
                    mode = (kubelet.get("authorization_mode") or "").strip() or "unknown"

                    if not present:
                        status = "ERROR"
                        reason = (
                            f"[{node_name}] 노드에서 kubelet 설정 파일(/var/lib/kubelet/config.yaml)을 읽을 수 없습니다. "
                            "해당 경로가 없거나 node-scanner Pod가 hostPath로 마운트하지 못했을 수 있습니다. "
                            "Kind/Minikube 등은 kubelet config 경로가 다를 수 있습니다."
                        )
                        remediation = (
                            "1) node-scanner DaemonSet 배포: kubectl apply -f k8s/node-scanner-daemonset.yaml\n"
                            "2) 노드에서 설정 경로 확인: 해당 노드에 /var/lib/kubelet/config.yaml 존재 여부 및 읽기 권한 확인\n"
                            "3) kubelet이 다른 경로를 쓰는 경우 node-scanner DaemonSet의 hostPath와 emit_kubelet() 경로를 환경에 맞게 수정"
                        )
                    elif mode == "AlwaysAllow":
                        status = "FAIL"
                        reason = "Kubelet authorization mode가 AlwaysAllow (보안 위험)"
                        remediation = (
                            "각 노드의 kubelet authorization mode를 Webhook으로 설정하고 "
                            "AlwaysAllow 사용을 피하세요.\n예: authorization:\n  mode: Webhook\n"
                        )
                    elif mode == "Webhook":
                        status = "PASS"
                        reason = "Kubelet authorization mode가 Webhook"
                        remediation = ""
                    elif mode == "unknown" and present:
                        # config는 읽었으나 authorization.mode가 없음 → Kubernetes 기본값(Webhook) 적용
                        status = "PASS"
                        reason = "Kubelet config 확인됨. authorization.mode 미기재로 Kubernetes 기본값(Webhook) 적용"
                        remediation = ""
                    else:
                        status = "ERROR"
                        reason = (
                            f"[{node_name}] node-scanner 로그에서 Kubelet 인가 모드(authorization_mode)를 확인할 수 없습니다. "
                            "DaemonSet 로그가 수집되지 않았거나, config에 authorization.mode가 없을 수 있습니다."
                        )
                        remediation = (
                            "1) node-scanner Pod 로그 확인: kubectl logs -n kube-system -l app=node-scanner --tail=200\n"
                            "2) NODE_SCANNER_KUBELET authorization_mode= 항목이 있는지 확인\n"
                            "3) 없으면 k8s/node-scanner-daemonset.yaml 적용 후 Pod가 정상 기동했는지 확인"
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
                            "kubelet_version": kubelet_version,
                            "pod": nd.get("pod"),
                            "authorization_mode": mode,
                            "kubelet_summary": kubelet,
                            "error": nd.get("error"),
                        },
                        "Remediation": remediation if status != "PASS" else (
                            "각 노드의 kubelet authorization mode를 Webhook으로 설정하고 "
                            "AlwaysAllow 사용을 피하세요.\n예: authorization:\n  mode: Webhook\n"
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
                    status = "ERROR"
                    reason = (
                        "ConfigMap(kube-system 내 kubelet 관련)에서 인가 설정을 찾을 수 없습니다. "
                        "node-scanner DaemonSet을 배포하면 노드별 config 파일을 직접 읽어 검사할 수 있습니다."
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
                        "kubelet_version": kubelet_version,
                        "authorization_mode": auth_check.get("mode"),
                        "error": auth_check.get("error"),
                    },
                    "Remediation": "" if status == "PASS" else (
                        "kubelet 설정에서 authorization.mode를 Webhook으로 설정하세요. "
                        "또는 node-scanner DaemonSet을 배포 후 다시 스캔하세요: kubectl apply -f k8s/node-scanner-daemonset.yaml"
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

