# 보안 점검 항목: etcd 데이터 디렉터리 권한 설정
# scanner/checks/etcd_data_directory_permissions.py
from .base import Check
import subprocess, json, traceback, stat, os

class EtcdDataDirectoryPermissionsCheck(Check):
    id = "CHK-M-FILE-003"
    name = "etcd 데이터 디렉터리 권한 설정 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    # etcd 데이터 디렉터리 경로 (일반적인 경로들)
    ETCD_DATA_DIRECTORIES = [
        "/var/lib/etcd",
        "/etc/kubernetes/manifests/etcd-data",
        "/opt/etcd/data"
    ]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _find_etcd_data_directory(self, pod_name, namespace, kubeconfig=''):
        """etcd 파드에서 데이터 디렉터리 경로 찾기"""
        try:
            # etcd 파드의 args에서 --data-dir 플래그 확인
            res = self._kubectl(["get", "pod", pod_name, "-n", namespace, "-o", "json"], kubeconfig)
            if res.returncode != 0:
                return None
            
            pod_data = json.loads(res.stdout)
            spec = pod_data.get("spec", {})
            containers = spec.get("containers", [])
            
            for container in containers:
                args = container.get("args", [])
                for i, arg in enumerate(args):
                    if arg == "--data-dir" and i + 1 < len(args):
                        return args[i + 1]
                    elif arg.startswith("--data-dir="):
                        return arg.split("=", 1)[1]
            
            # 기본 경로 반환
            return "/var/lib/etcd"
        except Exception:
            return None

    def _check_directory_permissions_via_pod(self, pod_name, namespace, dir_path, kubeconfig=''):
        """파드를 통해 디렉터리 권한 확인"""
        try:
            # ls -ld로 디렉터리 정보 확인
            cmd = ["exec", pod_name, "-n", namespace, "--", "ls", "-ld", dir_path]
            res = self._kubectl(cmd, kubeconfig)
            
            if res.returncode != 0:
                return None
            
            output = res.stdout.strip()
            if not output:
                return None
            
            # ls -ld 출력 파싱: drwx------ 3 root root 4096 Jan 1 00:00 /var/lib/etcd
            parts = output.split()
            if len(parts) < 9:
                return None
            
            permissions = parts[0]  # drwx------
            owner = parts[2]        # root
            group = parts[3]        # root
            
            # 권한을 숫자로 변환
            mode_str = permissions[1:]  # rwx------
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
                "path": dir_path,
                "permissions": permissions,
                "mode": mode,
                "owner": owner,
                "group": group,
                "exists": True
            }
        except Exception as e:
            return {"path": dir_path, "exists": False, "error": str(e)}

    def _check_directory_permissions_local(self, dir_path):
        """로컬 파일 시스템에서 직접 확인"""
        try:
            if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
                return {"path": dir_path, "exists": False}
            
            stat_info = os.stat(dir_path)
            mode = stat_info.st_mode
            dir_mode = stat.S_IMODE(mode)
            
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
                "path": dir_path,
                "permissions": oct(dir_mode),
                "mode": dir_mode,
                "owner": owner,
                "group": group,
                "exists": True
            }
        except Exception as e:
            return {"path": dir_path, "exists": False, "error": str(e)}

    def _validate_directory_permissions(self, dir_info):
        """디렉터리 권한이 요구사항을 만족하는지 확인"""
        if not dir_info.get("exists"):
            return {"valid": False, "reason": "디렉터리가 존재하지 않음"}
        
        owner = dir_info.get("owner", "")
        group = dir_info.get("group", "")
        mode = dir_info.get("mode", 0)
        
        issues = []
        
        # 소유자가 root 또는 etcd 전용 계정인지 확인
        # etcd 전용 계정은 보통 "etcd" 또는 "etcd-user" 등
        if owner != "root" and not owner.startswith("etcd"):
            issues.append(f"소유자가 root 또는 etcd 전용 계정이 아님 (현재: {owner})")
        
        # 소유 그룹이 root 또는 etcd 전용 그룹인지 확인
        if group != "root" and not group.startswith("etcd"):
            issues.append(f"소유 그룹이 root 또는 etcd 전용 그룹이 아님 (현재: {group})")
        
        # 권한이 700 이하인지 확인 (700 = 0o700 = 448)
        # 700: rwx------ (owner만 읽기/쓰기/실행)
        if mode > 448:  # 700 = 448 (0o700)
            issues.append(f"권한이 700보다 큼 (현재: {oct(mode)} = {mode})")
        
        # other에 접근 권한이 있으면 안됨
        if mode & 0o007:  # other read/write/execute
            issues.append("other에 접근 권한이 있음 (700 권한 필요)")
        
        # group에 접근 권한이 있으면 안됨 (700은 group 권한 없음)
        if mode & 0o070:  # group read/write/execute
            issues.append("group에 접근 권한이 있음 (700 권한 필요)")
        
        if issues:
            return {"valid": False, "reason": "; ".join(issues)}
        else:
            return {"valid": True, "reason": "디렉터리 권한 설정이 적절함"}

    def run(self, kubeconfig=''):
        findings = []
        
        try:
            # 1) etcd 파드 찾기
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
            
            # etcd 파드 찾기
            etcd_pods = []
            for it in pods.get("items", []):
                name = it.get("metadata", {}).get("name", "")
                if "etcd" in name.lower() and "kube-apiserver" not in name:
                    etcd_pods.append(it)
            
            # 2) etcd 데이터 디렉터리 찾기 및 권한 확인
            checked_directories = {}
            
            if etcd_pods:
                # 첫 번째 etcd 파드 사용
                pod = etcd_pods[0]
                pod_name = pod.get("metadata", {}).get("name")
                namespace = pod.get("metadata", {}).get("namespace", "kube-system")
                
                # etcd 파드에서 데이터 디렉터리 경로 찾기
                etcd_data_dir = self._find_etcd_data_directory(pod_name, namespace, kubeconfig)
                
                # 확인할 디렉터리 목록 (etcd 파드에서 찾은 경로 우선)
                directories_to_check = []
                if etcd_data_dir:
                    directories_to_check.append(etcd_data_dir)
                directories_to_check.extend(self.ETCD_DATA_DIRECTORIES)
                
                # 중복 제거
                directories_to_check = list(dict.fromkeys(directories_to_check))
                
                for dir_path in directories_to_check:
                    dir_info = self._check_directory_permissions_via_pod(pod_name, namespace, dir_path, kubeconfig)
                    if dir_info and dir_info.get("exists"):
                        checked_directories[dir_path] = dir_info
                        break  # 첫 번째 존재하는 디렉터리만 확인
            else:
                # 로컬 파일 시스템에서 직접 확인
                for dir_path in self.ETCD_DATA_DIRECTORIES:
                    dir_info = self._check_directory_permissions_local(dir_path)
                    if dir_info and dir_info.get("exists"):
                        checked_directories[dir_path] = dir_info
                        break
            
            # 3) 디렉터리 권한 검증
            failed_directories = []
            
            for dir_path, dir_info in checked_directories.items():
                validation = self._validate_directory_permissions(dir_info)
                
                if not validation["valid"]:
                    failed_directories.append({
                        "path": dir_path,
                        "info": dir_info,
                        "reason": validation["reason"]
                    })
            
            # 4) 결과 생성
            if failed_directories:
                for failed in failed_directories:
                    findings.append({
                        "CheckID": self.id,
                        "Result": "FAIL",
                        "ObjectType": "Directory",
                        "ObjectName": failed["path"],
                        "Namespace": "N/A",
                        "Reason": f"etcd 데이터 디렉터리 권한 설정이 부적절함: {failed['reason']}",
                        "Evidence": {
                            "path": failed["path"],
                            "owner": failed["info"].get("owner"),
                            "group": failed["info"].get("group"),
                            "mode": failed["info"].get("mode"),
                            "permissions": failed["info"].get("permissions")
                        },
                        "Remediation": (
                            f"etcd 데이터 디렉터리 {failed['path']}의 권한을 수정하세요:\n"
                            f"sudo chown root:root {failed['path']}\n"
                            f"sudo chmod 700 {failed['path']}\n\n"
                            "권장 설정:\n"
                            "- 소유자: root 또는 etcd 전용 계정\n"
                            "- 소유 그룹: root 또는 etcd 전용 그룹\n"
                            "- 권한: 700 (rwx------)"
                        )
                    })
            elif checked_directories:
                # 모든 디렉터리가 적절히 설정됨
                findings.append({
                    "CheckID": self.id,
                    "Result": "PASS",
                    "ObjectType": "Directory",
                    "ObjectName": list(checked_directories.keys())[0],
                    "Namespace": "N/A",
                    "Reason": "etcd 데이터 디렉터리 권한이 적절히 설정됨",
                    "Evidence": {
                        "path": list(checked_directories.keys())[0],
                        "owner": list(checked_directories.values())[0].get("owner"),
                        "group": list(checked_directories.values())[0].get("group"),
                        "mode": list(checked_directories.values())[0].get("mode")
                    },
                    "Remediation": ""
                })
            else:
                # 디렉터리를 찾을 수 없음
                findings.append({
                    "CheckID": self.id,
                    "Result": "WARN",
                    "ObjectType": "Directory",
                    "ObjectName": "etcd-data",
                    "Namespace": "N/A",
                    "Reason": "etcd 데이터 디렉터리를 찾을 수 없음",
                    "Evidence": {"searched_directories": self.ETCD_DATA_DIRECTORIES},
                    "Remediation": (
                        "컨트롤플레인 노드에 직접 접근하여 etcd 데이터 디렉터리 권한을 확인하세요:\n"
                        "ls -ald /var/lib/etcd\n\n"
                        "권장 설정:\n"
                        "- 소유자: root 또는 etcd 전용 계정\n"
                        "- 소유 그룹: root 또는 etcd 전용 그룹\n"
                        "- 권한: 700 (rwx------)\n\n"
                        "수정 명령:\n"
                        "sudo chown root:root /var/lib/etcd\n"
                        "sudo chmod 700 /var/lib/etcd"
                    )
                })
            
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "예외 발생: " + str(e),
                "Evidence": {"error": str(e), "trace": traceback.format_exc()},
                "Remediation": "컨트롤플레인 노드에 직접 접근하여 etcd 데이터 디렉터리 권한을 확인하세요"
            }]
        
        if not findings:
            findings.append({
                "CheckID": self.id,
                "Result": "WARN",
                "ObjectType": "Cluster",
                "ObjectName": "ALL",
                "Namespace": "N/A",
                "Reason": "etcd 파드를 찾을 수 없어 데이터 디렉터리 권한을 확인할 수 없음",
                "Evidence": {},
                "Remediation": (
                    "컨트롤플레인 노드에 직접 접근하여 etcd 데이터 디렉터리 권한을 확인하세요:\n"
                    "ls -ald /var/lib/etcd\n\n"
                    "권장 설정:\n"
                    "- 소유자: root 또는 etcd 전용 계정\n"
                    "- 소유 그룹: root 또는 etcd 전용 그룹\n"
                    "- 권한: 700 (rwx------)\n\n"
                    "수정 명령:\n"
                    "sudo chown root:root /var/lib/etcd\n"
                    "sudo chmod 700 /var/lib/etcd"
                )
            })
        
        return findings




