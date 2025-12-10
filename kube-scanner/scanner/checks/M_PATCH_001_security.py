# 보안 점검 항목: 최신 보안 패치 적용
# scanner/checks/security_patches.py
from .base import Check
import subprocess, json, traceback, re

class SecurityPatchesCheck(Check):
    id = "CHK-M-PATCH-001"
    name = "최신 보안 패치 적용 검사"
    category = "ControlPlane"
    severity = "High"
    points = 4
    risk_level = 8
    description = "주기적인 패치 적용을 통하여 보안성 및 시스템 안전성을 확보하는 것이 시스템 운용의 중요한 요소이다. 서비스 중인 시스템에서 패치 적용에 따라 발생하는 서비스 영향도를 확인하고 패치 적용 시 많은 부분을 고려해야 한다."
    recommended_setting = "최신 보안 패치가 적용되거나 보안 취약점이 존재하지 않는 버전을 사용하는 경우"
    verification_command = "kubectl version"

    # 알려진 취약한 Kubernetes 버전 (예시 - 실제로는 최신 CVE 데이터베이스와 연동 필요)
    # 이는 예시이며, 실제로는 외부 CVE 데이터베이스와 연동하거나 정기적으로 업데이트 필요
    KNOWN_VULNERABLE_VERSIONS = {
        # 예시: "v1.25.0": ["CVE-2023-XXXXX", "CVE-2023-YYYYY"],
    }

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _parse_kubectl_version(self, version_output):
        """kubectl version 출력 파싱"""
        versions = {}
        try:
            # Client Version: v1.28.0
            # Server Version: v1.28.0
            for line in version_output.split('\n'):
                if 'Client Version:' in line:
                    match = re.search(r'v(\d+)\.(\d+)\.(\d+)', line)
                    if match:
                        versions['client'] = {
                            'major': int(match.group(1)),
                            'minor': int(match.group(2)),
                            'patch': int(match.group(3)),
                            'full': match.group(0)
                        }
                elif 'Server Version:' in line:
                    match = re.search(r'v(\d+)\.(\d+)\.(\d+)', line)
                    if match:
                        versions['server'] = {
                            'major': int(match.group(1)),
                            'minor': int(match.group(2)),
                            'patch': int(match.group(3)),
                            'full': match.group(0)
                        }
        except Exception as e:
            pass
        
        return versions

    def _check_version_vulnerabilities(self, version):
        """버전의 알려진 취약점 확인"""
        version_str = version.get('full', '')
        if version_str in self.KNOWN_VULNERABLE_VERSIONS:
            return {
                "vulnerable": True,
                "cves": self.KNOWN_VULNERABLE_VERSIONS[version_str],
                "reason": f"알려진 취약점이 있는 버전: {', '.join(self.KNOWN_VULNERABLE_VERSIONS[version_str])}"
            }
        return {"vulnerable": False, "reason": "알려진 취약점 없음"}

    def _get_latest_stable_version(self):
        """최신 안정 버전 확인 (실제로는 Kubernetes 공식 API 또는 GitHub에서 가져와야 함)"""
        # 실제 구현 시에는 GitHub API나 Kubernetes 공식 사이트에서 최신 버전 정보를 가져와야 함
        # 여기서는 예시로 None 반환
        return None

    def _compare_versions(self, current, latest):
        """버전 비교"""
        if not latest:
            return {"outdated": False, "reason": "최신 버전 정보를 가져올 수 없음"}
        
        # 간단한 버전 비교 (실제로는 더 정교한 비교 필요)
        if (current['major'] < latest['major'] or
            (current['major'] == latest['major'] and current['minor'] < latest['minor']) or
            (current['major'] == latest['major'] and current['minor'] == latest['minor'] and current['patch'] < latest['patch'])):
            return {
                "outdated": True,
                "reason": f"최신 버전보다 낮음 (현재: {current['full']}, 최신: {latest['full']})"
            }
        
        return {"outdated": False, "reason": "최신 버전 또는 그 이상"}

    def run(self, kubeconfig=''):
        findings = []
        
        try:
            # kubectl version 명령 실행
            res = self._kubectl(["version", "--output=json"], kubeconfig)
            
            if res.returncode != 0:
                # JSON 형식이 안되면 일반 출력 시도
                res = self._kubectl(["version"], kubeconfig)
                if res.returncode != 0:
                    return [{
                        "CheckID": self.id,
                        "Result": "ERROR",
                        "Reason": "kubectl version 실행 실패: " + (res.stderr or res.stdout).strip(),
                        "Evidence": {},
                        "Remediation": "kubectl 접근 권한 확인"
                    }]
                
                # 일반 출력 파싱
                versions = self._parse_kubectl_version(res.stdout)
            else:
                # JSON 출력 파싱
                try:
                    version_data = json.loads(res.stdout)
                    versions = {}
                    
                    if "clientVersion" in version_data:
                        cv = version_data["clientVersion"]
                        versions['client'] = {
                            'major': int(cv.get('major', 0)),
                            'minor': int(cv.get('minor', 0)),
                            'patch': int(cv.get('gitVersion', 'v0.0.0').split('.')[2].split('-')[0]) if '.' in cv.get('gitVersion', '') else 0,
                            'full': cv.get('gitVersion', '')
                        }
                    
                    if "serverVersion" in version_data:
                        sv = version_data["serverVersion"]
                        versions['server'] = {
                            'major': int(sv.get('major', 0)),
                            'minor': int(sv.get('minor', 0)),
                            'patch': int(sv.get('gitVersion', 'v0.0.0').split('.')[2].split('-')[0]) if '.' in sv.get('gitVersion', '') else 0,
                            'full': sv.get('gitVersion', '')
                        }
                except Exception as e:
                    # JSON 파싱 실패 시 일반 출력 파싱
                    versions = self._parse_kubectl_version(res.stdout)
            
            if not versions:
                return [{
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "Reason": "Kubernetes 버전 정보를 파싱할 수 없음",
                    "Evidence": {"raw_output": res.stdout},
                    "Remediation": "kubectl version 명령 출력 확인"
                }]
            
            # 서버 버전 확인 (가장 중요)
            server_version = versions.get('server')
            client_version = versions.get('client')
            
            issues = []
            evidence = {
                "server_version": server_version.get('full') if server_version else "Unknown",
                "client_version": client_version.get('full') if client_version else "Unknown"
            }
            
            if server_version:
                # 알려진 취약점 확인
                vuln_check = self._check_version_vulnerabilities(server_version)
                if vuln_check.get("vulnerable"):
                    issues.append(vuln_check["reason"])
                    evidence["vulnerabilities"] = vuln_check.get("cves", [])
                
                # 최신 버전과 비교 (실제로는 외부 API 호출 필요)
                # latest = self._get_latest_stable_version()
                # if latest:
                #     version_check = self._compare_versions(server_version, latest)
                #     if version_check.get("outdated"):
                #         issues.append(version_check["reason"])
            
            # 클라이언트 버전 확인
            if client_version:
                vuln_check = self._check_version_vulnerabilities(client_version)
                if vuln_check.get("vulnerable"):
                    issues.append(f"클라이언트: {vuln_check['reason']}")
            
            # 결과 생성
            if issues:
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Cluster",
                    "ObjectName": "Kubernetes",
                    "Namespace": "N/A",
                    "Reason": "; ".join(issues),
                    "Evidence": evidence,
                    "Remediation": (
                        "Kubernetes를 최신 보안 패치가 적용된 버전으로 업그레이드하세요.\n\n"
                        "업그레이드 방법:\n"
                        "1. Kubernetes 공식 문서에서 최신 안정 버전 확인\n"
                        "2. 업그레이드 계획 수립 (마이너 버전 업그레이드 시 주의)\n"
                        "3. 백업 수행\n"
                        "4. 컨트롤플레인 노드부터 순차적으로 업그레이드\n"
                        "5. 워커 노드 업그레이드\n\n"
                        "참고: https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/"
                    )
                })
            else:
                # 알려진 취약점이 없음 (하지만 최신 버전인지는 확인 불가)
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Cluster",
                    "ObjectName": "Kubernetes",
                    "Namespace": "N/A",
                    "Reason": "알려진 취약점은 없지만, 최신 버전 여부는 확인되지 않음",
                    "Evidence": evidence,
                    "Remediation": (
                        "정기적으로 Kubernetes 버전을 확인하고 최신 보안 패치를 적용하세요.\n\n"
                        "버전 확인:\n"
                        "kubectl version\n\n"
                        "최신 버전 확인:\n"
                        "- Kubernetes 공식 릴리스 페이지: https://github.com/kubernetes/kubernetes/releases\n"
                        "- CVE 데이터베이스 확인: https://cve.mitre.org/\n\n"
                        "현재 버전: " + evidence.get("server_version", "Unknown")
                    )
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "kubectl version 명령을 직접 실행하여 버전을 확인하세요"
            }]
        
        return findings




