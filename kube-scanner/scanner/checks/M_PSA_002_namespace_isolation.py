# 보안 점검 항목: 네임스페이스 공유 금지
# scanner/checks/namespace_isolation.py
from .base import Check
from typing import List, Dict
from kubernetes import client
import traceback

class NamespaceIsolationCheck(Check):
    id = "CHK-M-PSA-002"
    name = "네임스페이스 공유 금지 검사 (hostNetwork/hostPID/hostIPC)"
    category = "Pod"
    severity = "High"
    points = 6
    risk_level = 9
    description = "파드의 컨테이너는 일반적으로 별도의 리눅스 네임스페이스에서 실행되므로 프로세스가 다른 컨테이너 또는 노드의 기본 네임스페이스에서 실행 중인 프로세스와 분리된다. 파드의 스펙에서 hostNetwork 옵션을 true로 설정하여 가상 네트워크 어댑터 대신 노드의 실제 네트워크 어댑터를 사용할 수 있으며 그 결과 해당 파드는 노드의 인터페이스를 사용하게 된다. 또한, hostNetwork 옵션과 유사한 파드 스펙 속성으로 hostPID와 hostIPC가 있다. 이를 true로 설정하면 파드의 컨테이너는 노드의 PID와 IPC 네임스페이스를 사용해 컨테이너에서 실행 중인 프로세스가 노드의 다른 프로세스를 보거나 IPC로 이들과 통신할 수 있다. 따라서, PSA(Pod Security Admission) 설정을 통해 호스트 IPC, PID, 네트워크 네임스페이스 사용을 방지하여 불필요한 권한을 제거해야 한다."
    recommended_setting = "네임스페이스 공유 금지 설정이 적용된 경우\n- hostNetwork=false\n- hostPID=false\n- hostIPC=false"
    verification_command = "kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true)'"

    def run(self, k8s_client) -> List[Dict]:
        findings = []
        try:
            v1 = k8s_client.CoreV1Api()
            
            # Control plane 및 시스템 컴포넌트는 호스트 네임스페이스 공유가 필요하므로 제외
            # - kube-apiserver-*: API 서버, 호스트 네트워크 접근 필요
            # - kube-controller-manager-*: 컨트롤러 매니저, 호스트 네트워크 접근 필요
            # - kube-scheduler-*: 스케줄러, 호스트 네트워크 접근 필요
            # - etcd-*: etcd 데이터 저장소, 호스트 네트워크/파일시스템 접근 필요
            # - kube-proxy-*: 네트워크 프록시, 호스트 네트워크 접근 필요
            # - storage-provisioner: 스토리지 프로비저너, 호스트 파일시스템 접근 필요
            # - coredns-*: CoreDNS, 호스트 네트워크 접근 필요
            EXCLUDED_POD_PREFIXES = [
                "kube-apiserver-",
                "kube-controller-manager-",
                "kube-scheduler-",
                "etcd-",
                "kube-proxy-",
                "storage-provisioner",
                "coredns-"
            ]
            
            # 1) 모든 파드에서 hostNetwork, hostPID, hostIPC 사용 확인
            pods = v1.list_pod_for_all_namespaces(watch=False)
            
            for p in pods.items:
                spec = p.spec or {}
                pod_name = p.metadata.name
                namespace = p.metadata.namespace
                
                # Control plane 및 시스템 컴포넌트 제외 (prefix 기반)
                is_excluded = any(pod_name.startswith(prefix) for prefix in EXCLUDED_POD_PREFIXES)
                if is_excluded:
                    continue
                
                violations = []
                evidence = {
                    "pod": pod_name,
                    "namespace": namespace,
                    "nodeName": getattr(spec, "node_name", None),
                    "pod_uid": p.metadata.uid
                }
                
                # hostNetwork 확인
                if getattr(spec, "host_network", False):
                    violations.append("hostNetwork=true")
                    evidence["hostNetwork"] = True
                
                # hostPID 확인
                if getattr(spec, "host_pid", False):
                    violations.append("hostPID=true")
                    evidence["hostPID"] = True
                
                # hostIPC 확인
                if getattr(spec, "host_ipc", False):
                    violations.append("hostIPC=true")
                    evidence["hostIPC"] = True
                
                if violations:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "FAIL",
                        "ObjectType": "Pod",
                        "ObjectName": pod_name,
                        "Namespace": namespace,
                        "Reason": f"호스트 네임스페이스 공유 사용: {', '.join(violations)}",
                        "Evidence": evidence,
                        "Remediation": (
                            f"파드 {pod_name}의 spec에서 다음 설정을 false로 변경하세요:\n"
                            "- hostNetwork: false\n"
                            "- hostPID: false\n"
                            "- hostIPC: false\n\n"
                            "또는 PSA(Pod Security Admission)를 사용하여 네임스페이스 레벨에서 제한하세요."
                        ),
                        "Severity": self.severity
                    })
            
            # 2) PSA(Pod Security Admission) 설정 확인
            # 네임스페이스 레벨에서 pod-security.kubernetes.io/enforce 레이블 확인
            namespaces = v1.list_namespace(watch=False)
            psa_findings = []
            
            for ns in namespaces.items:
                ns_name = ns.metadata.name
                labels = ns.metadata.labels or {}
                
                # PSA 레이블 확인
                enforce_label = labels.get("pod-security.kubernetes.io/enforce")
                audit_label = labels.get("pod-security.kubernetes.io/audit")
                warn_label = labels.get("pod-security.kubernetes.io/warn")
                
                # restricted 레벨은 hostNetwork, hostPID, hostIPC를 모두 차단
                # baseline 레벨은 hostNetwork만 차단
                # privileged 레벨은 제한 없음
                
                if enforce_label:
                    if enforce_label == "privileged":
                        # privileged는 제한이 없으므로 WARN
                        psa_findings.append({
                            "CheckID": self.id,
                            "Result": "WARN",
                            "ObjectType": "Namespace",
                            "ObjectName": ns_name,
                            "Namespace": ns_name,
                            "Reason": f"PSA enforce 레벨이 'privileged'로 설정됨 (호스트 네임스페이스 공유 제한 없음)",
                            "Evidence": {
                                "enforce": enforce_label,
                                "audit": audit_label,
                                "warn": warn_label
                            },
                            "Remediation": (
                                f"네임스페이스 {ns_name}의 PSA 레벨을 'baseline' 또는 'restricted'로 변경하세요:\n"
                                f"kubectl label namespace {ns_name} pod-security.kubernetes.io/enforce=baseline --overwrite\n"
                                "또는\n"
                                f"kubectl label namespace {ns_name} pod-security.kubernetes.io/enforce=restricted --overwrite"
                            ),
                            "Severity": self.severity
                        })
                    elif enforce_label == "baseline":
                        # baseline은 hostNetwork만 차단, hostPID/hostIPC는 허용
                        psa_findings.append({
                            "CheckID": self.id,
                            "Result": "WARN",
                            "ObjectType": "Namespace",
                            "ObjectName": ns_name,
                            "Namespace": ns_name,
                            "Reason": f"PSA enforce 레벨이 'baseline'로 설정됨 (hostPID, hostIPC는 허용됨)",
                            "Evidence": {
                                "enforce": enforce_label,
                                "audit": audit_label,
                                "warn": warn_label
                            },
                            "Remediation": (
                                f"더 강한 보안을 위해 네임스페이스 {ns_name}의 PSA 레벨을 'restricted'로 변경하세요:\n"
                                f"kubectl label namespace {ns_name} pod-security.kubernetes.io/enforce=restricted --overwrite"
                            ),
                            "Severity": self.severity
                        })
                    # restricted는 PASS (별도로 추가하지 않음)
                else:
                    # PSA 레이블이 없음
                    psa_findings.append({
                        "CheckID": self.id,
                        "Result": "WARN",
                        "ObjectType": "Namespace",
                        "ObjectName": ns_name,
                        "Namespace": ns_name,
                        "Reason": f"PSA(Pod Security Admission) 레이블이 설정되지 않음 (호스트 네임스페이스 공유 제한 없음)",
                        "Evidence": {
                            "enforce": enforce_label,
                            "audit": audit_label,
                            "warn": warn_label
                        },
                        "Remediation": (
                            f"네임스페이스 {ns_name}에 PSA 레이블을 추가하여 호스트 네임스페이스 공유를 제한하세요:\n"
                            f"kubectl label namespace {ns_name} pod-security.kubernetes.io/enforce=restricted --overwrite\n"
                            f"kubectl label namespace {ns_name} pod-security.kubernetes.io/audit=restricted --overwrite\n"
                            f"kubectl label namespace {ns_name} pod-security.kubernetes.io/warn=restricted --overwrite"
                        ),
                        "Severity": self.severity
                    })
            
            findings.extend(psa_findings)
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "",
                "Severity": self.severity
            }]
        
        # 파드 레벨 위반이 없고 PSA도 적절히 설정된 경우 PASS
        if not findings:
            return [{
                "CheckID": self.id,
                "Result": "PASS",
                "ObjectType": "Cluster",
                "ObjectName": "ALL",
                "Namespace": "N/A",
                "Reason": "호스트 네임스페이스 공유를 사용하는 파드가 없고, PSA 설정이 적절함",
                "Evidence": {},
                "Remediation": "",
                "Severity": self.severity
            }]
        
        return findings




