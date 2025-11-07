# 보안 점검 항목: Pod hostNetwork 사용 검사 (네트워크 격리 확인)
from .base import Check
from typing import Dict, List
from kubernetes import client
import traceback

class HostNetworkCheck(Check):
    id = "CHK-001"
    name = "Pod hostNetwork 검사"
    category = "Pod"
    severity = "High"
    points = 6

    def run(self, k8s_client) -> List[Dict]:
        findings = []
        try:
            v1 = k8s_client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for p in pods.items:
                spec = p.spec or {}
                if getattr(spec, "host_network", False):
                    findings.append({
                        "CheckID": f"{self.id}",
                        "Result": "FAIL",
                        "ObjectType": "Pod",
                        "ObjectName": p.metadata.name,
                        "Namespace": p.metadata.namespace,
                        "Reason": "spec.hostNetwork == true",
                        "Evidence": {
                            "nodeName": spec.node_name,
                            "pod_uid": p.metadata.uid
                        },
                        "Remediation": "가능한 경우 hostNetwork:false로 변경하거나 별도 네트워크 네임스페이스 사용.",
                        "Severity": self.severity
                    })
        except Exception as e:
            return [{
                "CheckID": f"{self.id}",
                "Result": "ERROR",
                "Reason": "예외 발생",
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "",
                "Severity": self.severity
            }]
        # PASS 처리: findings가 비어있으면 PASS를 한 결과로 반환
        if not findings:
            return [{
                "CheckID": f"{self.id}",
                "Result": "PASS",
                "ObjectType": "Cluster",
                "ObjectName": "ALL",
                "Namespace": "N/A",
                "Reason": "No pods with hostNetwork=true found",
                "Evidence": {},
                "Remediation": "",
                "Severity": self.severity
            }]
        return findings
