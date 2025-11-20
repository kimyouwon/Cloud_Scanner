# 보안 점검 항목: 인증서 파일 권한 설정
# scanner/checks/certificate_file_permissions.py
from .base import Check
import subprocess, json, traceback, stat, os, re

class CertificateFilePermissionsCheck(Check):
    id = "CHK-M-FILE-002"
    name = "인증서 파일 권한 설정 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    # 확인할 디렉터리 및 파일 패턴
    CERT_DIRECTORIES = [
        "/etc/kubernetes/pki",
        "/var/lib/kubernetes"
    ]
    
    # 인증서 파일 확장자 (644 이하)
    CERT_EXTENSIONS = [".crt", ".pem", ".cert"]
    
    # 키 파일 확장자 (600 이하)
    KEY_EXTENSIONS = [".key"]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _find_certificate_files_via_pod(self, pod_name, namespace, directory, kubeconfig=''):
        """파드를 통해 인증서 및 키 파일 찾기"""
        files = []
        try:
            # find 명령으로 인증서 및 키 파일 찾기
            find_cmd = f"find {directory} -type f \\( -name '*.crt' -o -name '*.key' -o -name '*.pem' -o -name '*.cert' \\) 2>/dev/null"
            cmd = ["exec", pod_name, "-n", namespace, "--", "sh", "-c", find_cmd]
            res = self._kubectl(cmd, kubeconfig)
            
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.strip().split('\n'):
                    if line.strip():
                        files.append(line.strip())
        except Exception:
            pass
        
        return files

    def _check_file_permissions_via_pod(self, pod_name, namespace, file_path, kubeconfig=''):
        """파드를 통해 파일 권한 확인"""
        try:
            # ls -l로 파일 정보 확인
            cmd = ["exec", pod_name, "-n", namespace, "--", "ls", "-ld", file_path]
            res = self._kubectl(cmd, kubeconfig)
            
            if res.returncode != 0:
                return None
            
            output = res.stdout.strip()
            if not output:
                return None
            
            # ls -l 출력 파싱: -rw-r--r-- 1 root root 1234 Jan 1 00:00 /path/to/file
            parts = output.split()
            if len(parts) < 9:
                return None
            
            permissions = parts[0]  # -rw-r--r--
            owner = parts[2]        # root
            group = parts[3]        # root
            
            # 권한을 숫자로 변환
            mode_str = permissions[1:]  # rw-r--r--
            mode = 0
            if len(mode_str) >= 9:
                # owner 권한
                if mode_str[0] == 'r': mode += 400
                if mode_str[1] == 'w': mode += 200
                if mode_str[2] == 'x': mode += 100
                # group 권한
                if mode_str[3] == 'r': mode += 40
                if mode_str[4] == 'w': mode += 20
                if mode_str[5] == 'x': mode += 10
                # other 권한
                if mode_str[6] == 'r': mode += 4
                if mode_str[7] == 'w': mode += 2
                if mode_str[8] == 'x': mode += 1
            
            return {
                "path": file_path,
                "permissions": permissions,
                "mode": mode,
                "owner": owner,
                "group": group,
                "exists": True
            }
        except Exception as e:
            return {"path": file_path, "exists": False, "error": str(e)}

    def _check_file_permissions_local(self, file_path):
        """로컬 파일 시스템에서 직접 확인"""
        try:
            if not os.path.exists(file_path):
                return {"path": file_path, "exists": False}
            
            stat_info = os.stat(file_path)
            mode = stat_info.st_mode
            file_mode = stat.S_IMODE(mode)
            
            # 소유자 정보
            try:
                import pwd, grp
                owner_uid = stat_info.st_uid
                group_gid = stat_info.st_gid
                owner = pwd.getpwuid(owner_uid).pw_name
                group = grp.getgrgid(group_gid).gr_name
            except (ImportError, KeyError):
                owner = str(stat_info.st_uid)
                group = str(stat_info.st_gid)
            
            return {
                "path": file_path,
                "permissions": oct(file_mode),
                "mode": file_mode,
                "owner": owner,
                "group": group,
                "exists": True
            }
        except Exception as e:
            return {"path": file_path, "exists": False, "error": str(e)}

    def _is_certificate_file(self, file_path):
        """인증서 파일인지 확인"""
        file_lower = file_path.lower()
        return any(file_lower.endswith(ext) for ext in self.CERT_EXTENSIONS)

    def _is_key_file(self, file_path):
        """키 파일인지 확인"""
        file_lower = file_path.lower()
        return any(file_lower.endswith(ext) for ext in self.KEY_EXTENSIONS)

    def _validate_certificate_file_permissions(self, file_info, is_key_file=False):
        """인증서/키 파일 권한이 요구사항을 만족하는지 확인"""
        if not file_info.get("exists"):
            return {"valid": False, "reason": "파일이 존재하지 않음"}
        
        owner = file_info.get("owner", "")
        group = file_info.get("group", "")
        mode = file_info.get("mode", 0)
        
        issues = []
        
        # 소유자가 root인지 확인
        if owner != "root":
            issues.append(f"소유자가 root가 아님 (현재: {owner})")
        
        # 소유 그룹이 root인지 확인
        if group != "root":
            issues.append(f"소유 그룹이 root가 아님 (현재: {group})")
        
        if is_key_file:
            # 키 파일: 600 이하 (rw-------)
            if mode > 384:  # 600 = 384 (0o600)
                issues.append(f"키 파일 권한이 600보다 큼 (현재: {oct(mode)} = {mode})")
            
            # other에 읽기/쓰기 권한이 있으면 안됨
            if mode & 0o007:  # other read/write/execute
                issues.append("other에 접근 권한이 있음 (키 파일은 600 권한 필요)")
            
            # group에 읽기/쓰기 권한이 있으면 안됨
            if mode & 0o070:  # group read/write/execute
                issues.append("group에 접근 권한이 있음 (키 파일은 600 권한 필요)")
        else:
            # 인증서 파일: 644 이하 (rw-r--r--)
            if mode > 420:  # 644 = 420 (0o644)
                issues.append(f"인증서 파일 권한이 644보다 큼 (현재: {oct(mode)} = {mode})")
            
            # other에 쓰기 권한이 있으면 안됨
            if mode & 0o002:  # other write
                issues.append("other에 쓰기 권한이 있음")
            
            # group에 쓰기 권한이 있으면 안됨
            if mode & 0o020:  # group write
                issues.append("group에 쓰기 권한이 있음")
        
        if issues:
            return {"valid": False, "reason": "; ".join(issues)}
        else:
            file_type = "키 파일" if is_key_file else "인증서 파일"
            return {"valid": True, "reason": f"{file_type} 권한 설정이 적절함"}

    def run(self, kubeconfig=''):
        findings = []
        
        try:
            # 1) 컨트롤플레인 파드 찾기
            res = self._kubectl(["get", "pods", "-n", "kube-system", "-o", "json"], kubeconfig)
            if res.returncode != 0:
                return [{
                    "CheckID": self.id,
                    "Result": "ERROR",
                    "Reason": "kubectl 실행 실패: " + (res.stderr or res.stdout).strip(),
                    "Evidence": {},
                    "Remediation": "kubectl 접근 권한(특히 kube-system 조회) 확인"
                }]

            pods = json.loads(res.stdout)
            
            # 컨트롤플레인 파드 찾기
            control_plane_pods = []
            for it in pods.get("items", []):
                name = it.get("metadata", {}).get("name", "")
                if any(comp in name for comp in ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"]):
                    control_plane_pods.append(it)
            
            # 2) 인증서 및 키 파일 찾기
            all_files = []
            
            if control_plane_pods:
                # 첫 번째 컨트롤플레인 파드 사용
                pod = control_plane_pods[0]
                pod_name = pod.get("metadata", {}).get("name")
                namespace = pod.get("metadata", {}).get("namespace", "kube-system")
                
                for directory in self.CERT_DIRECTORIES:
                    files = self._find_certificate_files_via_pod(pod_name, namespace, directory, kubeconfig)
                    all_files.extend(files)
            else:
                # 로컬 파일 시스템에서 직접 찾기
                for directory in self.CERT_DIRECTORIES:
                    if os.path.exists(directory):
                        for root, dirs, filenames in os.walk(directory):
                            for filename in filenames:
                                file_path = os.path.join(root, filename)
                                if self._is_certificate_file(file_path) or self._is_key_file(file_path):
                                    all_files.append(file_path)
            
            if not all_files:
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Directory",
                    "ObjectName": "Certificate Directories",
                    "Namespace": "N/A",
                    "Reason": "인증서 및 키 파일을 찾을 수 없음",
                    "Evidence": {"directories": self.CERT_DIRECTORIES},
                    "Remediation": (
                        "컨트롤플레인 노드에 직접 접근하여 다음 디렉터리에서 인증서 및 키 파일을 확인하세요:\n" +
                        "\n".join(f"- {d}" for d in self.CERT_DIRECTORIES) +
                        "\n\n권장 설정:\n"
                        "- 인증서 파일(.crt, .pem): 소유자/그룹 root, 권한 644\n"
                        "- 키 파일(.key): 소유자/그룹 root, 권한 600"
                    )
                })
                return findings
            
            # 3) 각 파일의 권한 확인
            failed_files = []
            checked_count = 0
            
            for file_path in all_files:
                if control_plane_pods:
                    pod = control_plane_pods[0]
                    pod_name = pod.get("metadata", {}).get("name")
                    namespace = pod.get("metadata", {}).get("namespace", "kube-system")
                    file_info = self._check_file_permissions_via_pod(pod_name, namespace, file_path, kubeconfig)
                else:
                    file_info = self._check_file_permissions_local(file_path)
                
                if not file_info or not file_info.get("exists"):
                    continue
                
                checked_count += 1
                is_key = self._is_key_file(file_path)
                validation = self._validate_certificate_file_permissions(file_info, is_key)
                
                if not validation["valid"]:
                    failed_files.append({
                        "path": file_path,
                        "info": file_info,
                        "reason": validation["reason"],
                        "is_key": is_key
                    })
            
            # 4) 결과 생성
            if failed_files:
                for failed in failed_files:
                    file_type = "키 파일" if failed["is_key"] else "인증서 파일"
                    required_mode = "600" if failed["is_key"] else "644"
                    
                    findings.append({
                        "CheckID": self.id,
                        "Result": "FAIL",
                        "ObjectType": "File",
                        "ObjectName": failed["path"],
                        "Namespace": "N/A",
                        "Reason": f"{file_type} 권한 설정이 부적절함: {failed['reason']}",
                        "Evidence": {
                            "path": failed["path"],
                            "file_type": file_type,
                            "owner": failed["info"].get("owner"),
                            "group": failed["info"].get("group"),
                            "mode": failed["info"].get("mode"),
                            "permissions": failed["info"].get("permissions"),
                            "required_mode": required_mode
                        },
                        "Remediation": (
                            f"{file_type} {failed['path']}의 권한을 수정하세요:\n"
                            f"sudo chown root:root {failed['path']}\n"
                            f"sudo chmod {required_mode} {failed['path']}\n\n"
                            f"권장 설정:\n"
                            f"- 소유자: root\n"
                            f"- 소유 그룹: root\n"
                            f"- 권한: {required_mode} ({'rw-------' if failed['is_key'] else 'rw-r--r--'})"
                        )
                    })
            
            if not failed_files and checked_count > 0:
                # 모든 파일이 적절히 설정됨
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": f"확인된 모든 인증서 및 키 파일({checked_count}개)의 권한이 적절히 설정됨",
                    "Evidence": {"checked_files_count": checked_count},
                    "Remediation": ""
                })
            elif checked_count == 0:
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Directory",
                    "ObjectName": "Certificate Directories",
                    "Namespace": "N/A",
                    "Reason": "인증서 및 키 파일을 찾았지만 권한을 확인할 수 없음",
                    "Evidence": {"found_files": len(all_files)},
                    "Remediation": (
                        "컨트롤플레인 노드에 직접 접근하여 파일 권한을 확인하세요:\n"
                        "ls -l /etc/kubernetes/pki/*.crt\n"
                        "ls -l /etc/kubernetes/pki/*.key\n"
                        "ls -l /var/lib/kubernetes/*.pem\n\n"
                        "권장 설정:\n"
                        "- 인증서 파일: chmod 644, chown root:root\n"
                        "- 키 파일: chmod 600, chown root:root"
                    )
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "컨트롤플레인 노드에 직접 접근하여 인증서 파일 권한을 확인하세요"
            }]
        
        if not findings:
            findings.append({
                "CheckID": self.id,
                "Result": "WARN",
                "ObjectType": "Cluster",
                "ObjectName": "ALL",
                "Namespace": "N/A",
                "Reason": "컨트롤플레인 파드를 찾을 수 없어 인증서 파일 권한을 확인할 수 없음",
                "Evidence": {},
                "Remediation": (
                    "컨트롤플레인 노드에 직접 접근하여 다음 디렉터리의 인증서 및 키 파일 권한을 확인하세요:\n" +
                    "\n".join(f"- {d}" for d in self.CERT_DIRECTORIES) +
                    "\n\n권장 설정:\n"
                    "- 인증서 파일(.crt, .pem): 소유자/그룹 root, 권한 644\n"
                    "- 키 파일(.key): 소유자/그룹 root, 권한 600\n\n"
                    "수정 명령:\n"
                    "sudo chown root:root <file>\n"
                    "sudo chmod 644 <cert-file>  # 인증서 파일\n"
                    "sudo chmod 600 <key-file>    # 키 파일"
                )
            })
        
        return findings




