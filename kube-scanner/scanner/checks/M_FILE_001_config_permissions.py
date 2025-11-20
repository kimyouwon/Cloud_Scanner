# 보안 점검 항목: 환경설정 파일 권한 설정
# scanner/checks/config_file_permissions.py
from .base import Check
import subprocess, json, traceback, stat, os

class ConfigFilePermissionsCheck(Check):
    id = "CHK-M-FILE-001"
    name = "환경설정 파일 권한 설정 검사"
    category = "ControlPlane"
    severity = "High"
    points = 6

    # 확인할 환경설정 파일 목록
    CONFIG_FILES = [
        "/etc/kubernetes/manifests/kube-apiserver.yaml",
        "/etc/kubernetes/manifests/kube-controller-manager.yaml",
        "/etc/kubernetes/manifests/kube-scheduler.yaml",
        "/etc/kubernetes/manifests/etcd.yaml",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/scheduler.conf",
        "/etc/kubernetes/controller-manager.conf"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _check_file_permissions_via_pod(self, pod_name, namespace, file_path, kubeconfig=''):
        """
        파드를 통해 파일 권한 확인
        파드 내부에서 ls -l 명령으로 파일 정보 확인
        """
        try:
            # 파드 내부에서 파일 정보 확인
            # ls -l 형식: -rw-r--r-- 1 root root 1234 Jan 1 00:00 /path/to/file
            cmd = ["exec", pod_name, "-n", namespace, "--", "ls", "-ld", file_path]
            res = self._kubectl(cmd, kubeconfig)
            
            if res.returncode != 0:
                return None  # 파일이 없거나 접근 불가
            
            output = res.stdout.strip()
            if not output:
                return None
            
            # ls -l 출력 파싱
            # 형식: -rw-r--r-- 1 root root 1234 Jan 1 00:00 /path/to/file
            parts = output.split()
            if len(parts) < 9:
                return None
            
            permissions = parts[0]  # -rw-r--r--
            owner = parts[2]        # root
            group = parts[3]        # root
            
            # 권한을 숫자로 변환 (예: -rw-r--r-- -> 644)
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
        """로컬 파일 시스템에서 직접 확인 (컨트롤플레인 노드에서 실행 시)"""
        try:
            if not os.path.exists(file_path):
                return {"path": file_path, "exists": False}
            
            stat_info = os.stat(file_path)
            mode = stat_info.st_mode
            file_mode = stat.S_IMODE(mode)
            
            # 소유자 정보 (Unix/Linux)
            try:
                import pwd, grp
                owner_uid = stat_info.st_uid
                group_gid = stat_info.st_gid
                owner = pwd.getpwuid(owner_uid).pw_name
                group = grp.getgrgid(group_gid).gr_name
            except (ImportError, KeyError):
                owner = str(owner_uid)
                group = str(group_gid)
            
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

    def _validate_file_permissions(self, file_info):
        """파일 권한이 요구사항을 만족하는지 확인"""
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
        
        # 권한이 644 이하인지 확인 (644 = 0o644 = 420)
        # 644: rw-r--r-- (owner: rw-, group: r--, other: r--)
        # 755: rwxr-xr-x (755는 허용하지 않음, 644 이하만 허용)
        if mode > 420:  # 644 = 420 (0o644)
            issues.append(f"권한이 644보다 큼 (현재: {oct(mode)} = {mode})")
        
        # other에 쓰기 권한이 있으면 안됨
        if mode & 0o002:  # other write
            issues.append("other에 쓰기 권한이 있음")
        
        # group에 쓰기 권한이 있으면 안됨 (644는 group write 없음)
        if mode & 0o020:  # group write
            issues.append("group에 쓰기 권한이 있음")
        
        if issues:
            return {"valid": False, "reason": "; ".join(issues)}
        else:
            return {"valid": True, "reason": "권한 설정이 적절함"}

    def run(self, kubeconfig=''):
        findings = []
        
        try:
            # 1) 컨트롤플레인 파드 찾기 (파일 확인용)
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
            
            # 컨트롤플레인 파드 찾기 (kube-apiserver, etcd 등)
            control_plane_pods = []
            for it in pods.get("items", []):
                name = it.get("metadata", {}).get("name", "")
                # 컨트롤플레인 컴포넌트 파드 찾기
                if any(comp in name for comp in ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"]):
                    control_plane_pods.append(it)
            
            # 2) 파일 권한 확인
            # 방법 1: 파드를 통해 확인
            checked_files = {}
            
            if control_plane_pods:
                # 첫 번째 컨트롤플레인 파드 사용 (모든 파드가 같은 노드에 있으므로)
                pod = control_plane_pods[0]
                pod_name = pod.get("metadata", {}).get("name")
                namespace = pod.get("metadata", {}).get("namespace", "kube-system")
                
                for file_path in self.CONFIG_FILES:
                    file_info = self._check_file_permissions_via_pod(pod_name, namespace, file_path, kubeconfig)
                    if file_info:
                        checked_files[file_path] = file_info
            else:
                # 방법 2: 로컬 파일 시스템 확인 (컨트롤플레인 노드에서 직접 실행 시)
                for file_path in self.CONFIG_FILES:
                    file_info = self._check_file_permissions_local(file_path)
                    if file_info:
                        checked_files[file_path] = file_info
            
            # 3) 각 파일 검증
            failed_files = []
            missing_files = []
            
            for file_path in self.CONFIG_FILES:
                if file_path not in checked_files:
                    missing_files.append(file_path)
                    continue
                
                file_info = checked_files[file_path]
                validation = self._validate_file_permissions(file_info)
                
                if not validation["valid"]:
                    failed_files.append({
                        "path": file_path,
                        "info": file_info,
                        "reason": validation["reason"]
                    })
            
            # 4) 결과 생성
            if failed_files:
                for failed in failed_files:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "FAIL",
                        "ObjectType": "File",
                        "ObjectName": failed["path"],
                        "Namespace": "N/A",
                        "Reason": f"파일 권한 설정이 부적절함: {failed['reason']}",
                        "Evidence": {
                            "path": failed["path"],
                            "owner": failed["info"].get("owner"),
                            "group": failed["info"].get("group"),
                            "mode": failed["info"].get("mode"),
                            "permissions": failed["info"].get("permissions")
                        },
                        "Remediation": (
                            f"파일 {failed['path']}의 권한을 수정하세요:\n"
                            f"sudo chown root:root {failed['path']}\n"
                            f"sudo chmod 644 {failed['path']}\n\n"
                            "권장 설정:\n"
                            "- 소유자: root\n"
                            "- 소유 그룹: root\n"
                            "- 권한: 644 (rw-r--r--)"
                        )
                    })
            
            if missing_files:
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "File",
                    "ObjectName": "Multiple",
                    "Namespace": "N/A",
                    "Reason": f"다음 파일들을 확인할 수 없음: {', '.join(missing_files)}",
                    "Evidence": {"missing_files": missing_files},
                    "Remediation": (
                        "컨트롤플레인 노드에 직접 접근하여 다음 파일들의 권한을 확인하세요:\n" +
                        "\n".join(f"- {f}" for f in missing_files) +
                        "\n\n권장 설정:\n"
                        "- 소유자: root\n"
                        "- 소유 그룹: root\n"
                        "- 권한: 644 (rw-r--r--)\n\n"
                        "수정 명령:\n"
                        "sudo chown root:root <file>\n"
                        "sudo chmod 644 <file>"
                    )
                })
            
            if not failed_files and not missing_files:
                # 모든 파일이 적절히 설정됨
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Cluster",
                    "ObjectName": "ALL",
                    "Namespace": "N/A",
                    "Reason": "모든 환경설정 파일의 권한이 적절히 설정됨",
                    "Evidence": {"checked_files": list(checked_files.keys())},
                    "Remediation": ""
                })
            elif not failed_files and missing_files:
                # 일부 파일만 확인 불가 (WARN만 있음)
                pass  # 이미 WARN 추가됨
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "컨트롤플레인 노드에 직접 접근하여 파일 권한을 확인하세요"
            }]
        
        if not findings:
            # 아무것도 확인할 수 없음
            findings.append({
                "CheckID": self.id,
                "Result": "WARN",
                "ObjectType": "Cluster",
                "ObjectName": "ALL",
                "Namespace": "N/A",
                "Reason": "컨트롤플레인 파드를 찾을 수 없어 파일 권한을 확인할 수 없음",
                "Evidence": {},
                "Remediation": (
                    "컨트롤플레인 노드에 직접 접근하여 다음 파일들의 권한을 확인하세요:\n" +
                    "\n".join(f"- {f}" for f in self.CONFIG_FILES) +
                    "\n\n권장 설정:\n"
                    "- 소유자: root\n"
                    "- 소유 그룹: root\n"
                    "- 권한: 644 (rw-r--r--)\n\n"
                    "수정 명령:\n"
                    "sudo chown root:root <file>\n"
                    "sudo chmod 644 <file>"
                )
            })
        
        return findings




