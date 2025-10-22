from .base import Check
from typing import List, Dict
import traceback

class PrivilegedCheck(Check):
    id = "CHK-002"
    name = "Container privileged 검사"
    category = "Pod"
    severity = "High"

    def run(self, k8s_client) -> List[Dict]:
        findings = []
        try:
            v1 = k8s_client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for p in pods.items:
                for c in (p.spec.containers or []):
                    sc = c.security_context
                    if sc and getattr(sc, "privileged", False):
                        findings.append({
                            "CheckID": f"{self.id}",
                            "Result": "FAIL",
                            "ObjectType": "Container",
                            "ObjectName": c.name,
                            "Namespace": p.metadata.namespace,
                            "Reason": "container.securityContext.privileged == true",
                            "Evidence": {"pod": p.metadata.name},
                            "Remediation": "privileged:false 설정 또는 보다 세분화된 권한으로 대체",
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
        if not findings:
            return [{
                "CheckID": f"{self.id}",
                "Result": "PASS",
                "ObjectType": "Cluster",
                "ObjectName": "ALL",
                "Namespace": "N/A",
                "Reason": "No privileged containers found",
                "Evidence": {},
                "Remediation": "",
                "Severity": self.severity
            }]
        return findings
