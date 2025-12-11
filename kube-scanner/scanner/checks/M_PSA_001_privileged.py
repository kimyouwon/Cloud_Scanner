# 보안 점검 항목: 컨테이너 권한 제어
from .base import Check
from typing import List, Dict
import traceback

class PrivilegedCheck(Check):
    id = "CHK-M-PSA-001"
    name = "Container privileged 검사"
    category = "Pod"
    severity = "High"
    points = 7
    risk_level = 9
    description = "PodSecurityAdmission(이하 PSA)는 클러스터 및 네임스페이스 수준의 리소스로, 파드에 대해 서로 다른 격리 수준을 정의한다. PodSecurityStandard(이하 PSS)를 적용하기 위해 내장된 PSA Controller를 통해 수행된다. PSS 수준에 맞지 않은 Pod를 생성할 경우 설정된 PSS 수준에 따라 내장된 PSA Controller가 유효성을 검사한다. 따라서, 파드 내 컨테이너가 불필요한 권한을 가지지 않도록 PSA를 통해 PSS를 적용하여 운용해야 한다."
    recommended_setting = "PodSecurityAdmission 정책을 통해 컨테이너 권한을 제어한 경우\n- allowPrivilegeEscalation=false\n- runAsUser 설정\n- runAsNonRoot=true\n- capabilities.drop=ALL\n- seccompProfile 적용"
    verification_command = "kubectl get pods --all-namespaces -o json | jq '.items[].spec.containers[].securityContext.privileged'"

    def run(self, k8s_client) -> List[Dict]:
        findings = []
        try:
            v1 = k8s_client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for p in pods.items:
                # kube-proxy는 시스템 컴포넌트로 privileged 모드가 필요하므로 제외
                pod_name = p.metadata.name
                if "kube-proxy" in pod_name:
                    continue
                
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
