# 보안 점검 항목: Kubelet 인증 설정
# scanner/checks/kubelet_auth.py
from .base import Check
import subprocess, json, traceback

class KubeletAuthCheck(Check):
    id = "CHK-W-KUBELET-001"
    name = "인증 제어"
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
                    "Result": "ERROR",
                    "Reason": "노드가 없어 검사할 수 없음",
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
                        status = "ERROR"
                        reason = (
                            f"[{node_name}] 노드에서 kubelet 설정 파일(/var/lib/kubelet/config.yaml)을 읽을 수 없습니다. "
                            "해당 경로가 없거나 node-scanner Pod가 hostPath로 마운트하지 못했을 수 있습니다."
                        )
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
                            "각 노드의 /var/lib/kubelet/config.yaml에 clientCAFile 설정을 확인/추가하세요. "
                            "ERROR인 경우: 1) kubectl apply -f k8s/node-scanner-daemonset.yaml 배포 2) 노드에 해당 경로 존재 여부 확인\n"
                            "예: authentication:\n  x509:\n    clientCAFile: /etc/kubernetes/pki/ca.crt\n"
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
                    reason = "kubelet 인증 설정 점검 결과(ConfigMap 기반): clientCAFile 확인됨"
                elif config_check.get("has_auth") is False:
                    status = "FAIL"
                    reason = "Kubelet 인증 설정(clientCAFile)이 없음"
                else:
                    status = "ERROR"
                    reason = (
                        "ConfigMap(kube-system 내 kubelet 관련)에서 인증 설정(clientCAFile)을 찾을 수 없습니다. "
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
                        "source": config_check.get("source"),
                        "error": config_check.get("error"),
                    },
                    "Remediation": "" if status == "PASS" else (
                        "각 노드의 kubelet config에 clientCAFile을 설정하세요. "
                        "또는 node-scanner DaemonSet 배포 후 재스캔: kubectl apply -f k8s/node-scanner-daemonset.yaml"
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

