# 보안 점검 항목: Kubelet 인증 설정
# scanner/checks/kubelet_auth.py
from .base import Check
import subprocess, json, traceback

class KubeletAuthCheck(Check):
    id = "CHK-W-KUBELET-001"
    name = "Kubelet 인증 설정 검사"
    category = "Kubelet"
    severity = "High"
    points = 2
    risk_level = 8
    description = "Kubelet은 워커 노드에서 실행되는 주요 컴포넌트로, API Server와 통신하며 파드를 관리합니다. Kubelet 인증이 제대로 설정되지 않으면 비인가된 요청이 허용될 수 있습니다."
    recommended_setting = "Kubelet 인증이 설정된 경우\n- --client-ca-file 설정 (클라이언트 인증서 검증)"
    verification_command = "kubectl get nodes -o json | jq '.items[].status.nodeInfo.kubeletVersion'\n# 또는 노드에서 직접: ps aux | grep kubelet | grep client-ca-file"

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _check_kubelet_config_via_node(self, node_name, kubeconfig=''):
        """노드의 kubelet 설정 확인 (ConfigMap 또는 직접 접근)"""
        try:
            # kubelet 설정은 보통 ConfigMap으로 관리됨
            # kubelet-config-{version} 또는 kubelet-config 형식
            res = self._kubectl(["get", "configmap", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode == 0:
                configmaps = json.loads(res.stdout)
                for cm in configmaps.get("items", []):
                    cm_name = cm.get("metadata", {}).get("name", "")
                    if "kubelet" in cm_name.lower() and "config" in cm_name.lower():
                        data = cm.get("data", {})
                        # kubelet config.yaml 내용 확인
                        if "kubelet" in data or "config.yaml" in data:
                            config_content = data.get("kubelet", data.get("config.yaml", ""))
                            if "clientCAFile" in config_content or "authentication" in config_content:
                                return {"has_auth": True, "source": "configmap"}
            
            # 노드의 kubelet 설정 파일 직접 확인 시도 (DaemonSet을 통한 접근)
            # 일반적으로는 노드에 직접 접근해야 하지만, 여기서는 WARN 처리
            return {"has_auth": None, "source": "unknown"}
        except Exception as e:
            return {"has_auth": None, "error": str(e)}

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

            # node-scanner 기반 자동 판정 (가능할 때)
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
                    has_ca = kubelet.get("has_clientCAFile") == "true"

                    if not present:
                        status = "WARN"
                        reason = "kubelet config.yaml을 읽을 수 없어 인증 설정을 확인할 수 없음"
                    elif has_ca:
                        status = "PASS"
                        reason = "Kubelet 인증 설정(clientCAFile)이 확인됨"
                    else:
                        status = "FAIL"
                        reason = "Kubelet 인증 설정(clientCAFile)이 없음"

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
                            "kubelet_summary": kubelet,
                            "error": nd.get("error"),
                        },
                        "Remediation": (
                            "각 노드의 /var/lib/kubelet/config.yaml에 clientCAFile 설정을 확인/추가하세요.\n"
                            "예:\n"
                            "authentication:\n"
                            "  x509:\n"
                            "    clientCAFile: /etc/kubernetes/pki/ca.crt\n"
                        )
                    })

                return results

            # fallback: 기존 ConfigMap 기반(노드별 차이는 제한적)
            results = []
            for node in node_items:
                node_name = node.get("metadata", {}).get("name", "unknown")
                node_info = node.get("status", {}).get("nodeInfo", {})
                kubelet_version = node_info.get("kubeletVersion", "unknown")
                config_check = self._check_kubelet_config_via_node(node_name, kubeconfig)
                if config_check.get("has_auth") is True:
                    status = "PASS"
                elif config_check.get("has_auth") is False:
                    status = "FAIL"
                else:
                    status = "WARN"
                results.append({
                    "CheckID": self.id,
                    "Result": status,
                    "ObjectType": "Node",
                    "ObjectName": node_name,
                    "Namespace": "N/A",
                    "Reason": "kubelet 인증 설정 점검 결과(대체 경로: ConfigMap 기반)",
                    "Evidence": {
                        "node": node_name,
                        "kubelet_version": kubelet_version,
                        "source": config_check.get("source"),
                        "error": config_check.get("error"),
                    },
                    "Remediation": "node-scanner DaemonSet을 배포하면 노드별로 더 정확히 판정할 수 있습니다."
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

