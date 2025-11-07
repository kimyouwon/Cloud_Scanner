# 보안 점검 항목: etcd 암호화 적용
# scanner/checks/etcd_encryption.py
from .base import Check
import subprocess, json, traceback, os, base64
try:
    import yaml
except ImportError:
    yaml = None

class EtcdEncryptionCheck(Check):
    id = "CHK-ETCD-001"
    name = "etcd 암호화 적용 검사"
    category = "ControlPlane"
    severity = "Critical"
    points = 6

    # 안전한 암호화 방식 (aescbc 이상)
    SAFE_ENCRYPTION_METHODS = ["aescbc", "aesgcm", "secretbox", "kms"]

    def _kubectl(self, args, kubeconfig=''):
        cmd = ["kubectl"] + args
        if kubeconfig:
            cmd += ["--kubeconfig", kubeconfig]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _extract_flag(self, args_list, flag_name):
        """
        args_list: list of args strings
        flag_name: e.g., '--encryption-provider-config'
        반환: None(플래그 없음) or str(경로값)
        """
        for i, a in enumerate(args_list):
            if a.startswith(flag_name + "="):
                return a.split("=", 1)[1]
            if a == flag_name:
                # 다음 토큰이 값일 수 있음
                if i + 1 < len(args_list):
                    return args_list[i+1]
                return None
        return None

    def _check_encryption_config_from_pod(self, pod_spec, config_path):
        """
        파드의 volume 마운트 정보를 확인하여 설정 파일이 ConfigMap/Secret으로 마운트되어 있는지 확인
        마운트되어 있다면 실제 내용을 읽어서 암호화 방식 확인
        """
        volumes = pod_spec.get("volumes", [])
        volume_mounts = []
        for container in pod_spec.get("containers", []):
            volume_mounts.extend(container.get("volumeMounts", []))
        
        # config_path와 매칭되는 volume mount 찾기
        for vm in volume_mounts:
            mount_path = vm.get("mountPath", "")
            if config_path.startswith(mount_path):
                # 해당 volume 찾기
                volume_name = vm.get("name", "")
                for vol in volumes:
                    if vol.get("name") == volume_name:
                        # ConfigMap이나 Secret인지 확인
                        if "configMap" in vol:
                            cm_name = vol["configMap"].get("name", "")
                            # ConfigMap 내용 읽기 시도
                            return self._read_configmap_content(cm_name, config_path, mount_path)
                        elif "secret" in vol:
                            secret_name = vol["secret"].get("secretName", "")
                            # Secret 내용 읽기 시도
                            return self._read_secret_content(secret_name, config_path, mount_path)
        return None
    
    def _read_configmap_content(self, cm_name, config_path, mount_path):
        """ConfigMap에서 설정 파일 내용 읽기"""
        try:
            res = self._kubectl(["get", "configmap", cm_name, "-n", "kube-system", "-o", "json"])
            if res.returncode == 0:
                cm_data = json.loads(res.stdout)
                # mount_path를 제거한 상대 경로 계산
                relative_path = config_path.replace(mount_path, "").lstrip("/")
                # ConfigMap의 data에서 해당 키 찾기
                data = cm_data.get("data", {})
                # 파일명으로 찾기 (예: encryption-config.yaml)
                filename = os.path.basename(config_path)
                if filename in data:
                    return self._parse_encryption_config(data[filename])
        except Exception:
            pass
        return None
    
    def _read_secret_content(self, secret_name, config_path, mount_path):
        """Secret에서 설정 파일 내용 읽기"""
        try:
            res = self._kubectl(["get", "secret", secret_name, "-n", "kube-system", "-o", "json"])
            if res.returncode == 0:
                secret_data = json.loads(res.stdout)
                # Secret은 base64 인코딩되어 있음
                data = secret_data.get("data", {})
                filename = os.path.basename(config_path)
                if filename in data:
                    decoded = base64.b64decode(data[filename]).decode('utf-8')
                    return self._parse_encryption_config(decoded)
        except Exception:
            pass
        return None
    
    def _parse_encryption_config(self, config_content):
        """
        암호화 설정 파일 내용을 파싱하여 사용된 암호화 방식 확인
        YAML 형식의 EncryptionConfiguration 파싱
        """
        if yaml is None:
            return {"status": "unknown", "reason": "yaml 모듈이 설치되지 않음 (pip install pyyaml 필요)"}
        
        try:
            config = yaml.safe_load(config_content)
            resources = config.get("resources", [])
            
            encryption_methods = []
            for resource in resources:
                providers = resource.get("providers", [])
                for provider in providers:
                    # provider는 dict 형태: {"aescbc": {...}} 또는 {"identity": {}}
                    for method_name in provider.keys():
                        if method_name != "identity":  # identity는 암호화 안함
                            encryption_methods.append(method_name.lower())
            
            if not encryption_methods:
                return {"status": "unsafe", "reason": "identity provider만 사용됨 (암호화 없음)"}
            
            # 안전한 암호화 방식인지 확인
            safe_methods = [m for m in encryption_methods if m in [s.lower() for s in self.SAFE_ENCRYPTION_METHODS]]
            unsafe_methods = [m for m in encryption_methods if m not in [s.lower() for s in self.SAFE_ENCRYPTION_METHODS]]
            
            if unsafe_methods:
                return {
                    "status": "unsafe",
                    "reason": f"안전하지 않은 암호화 방식 사용: {', '.join(unsafe_methods)}",
                    "methods": encryption_methods
                }
            else:
                return {
                    "status": "safe",
                    "reason": f"안전한 암호화 방식 사용: {', '.join(safe_methods)}",
                    "methods": encryption_methods
                }
        except Exception as e:
            return {"status": "unknown", "reason": f"설정 파일 파싱 실패: {str(e)}"}

    def run(self, kubeconfig=''):
        try:
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
        except Exception as e:
            return [{
                "CheckID": self.id,
                "Result": "ERROR",
                "Reason": "kubectl 출력 파싱 실패: " + str(e),
                "Evidence": {"trace": traceback.format_exc()},
                "Remediation": "kubectl 출력 확인"
            }]

        # kube-apiserver 관련 파드 수집
        apiserver_pods = []
        for it in pods.get("items", []):
            name = it.get("metadata", {}).get("name", "")
            if "kube-apiserver" in name:
                apiserver_pods.append(it)

        if not apiserver_pods:
            # 관리형 컨트롤플레인 또는 권한 부족 가능
            return [{
                "CheckID": self.id,
                "Result": "WARN",
                "Reason": "kube-system에서 kube-apiserver 파드를 찾지 못함 (관리형 컨트롤플레인일 수 있음 또는 권한 부족)",
                "Evidence": {"kube_system_pod_count": len(pods.get("items", []))},
                "Remediation": "관리형 클러스터이면 클라우드 콘솔/문서 확인. 자체관리라면 컨트롤플레인에서 매니페스트 확인"
            }]

        findings = []
        for p in apiserver_pods:
            meta = p.get("metadata", {})
            pod_name = meta.get("name")
            spec = p.get("spec", {}) or {}
            containers = spec.get("containers", []) or []

            args_list = []
            for c in containers:
                if c.get("command"):
                    args_list += c.get("command")
                if c.get("args"):
                    args_list += c.get("args")

            # --encryption-provider-config 플래그 확인
            encryption_config = self._extract_flag(args_list, "--encryption-provider-config")

            if encryption_config is None:
                # 플래그가 없음 -> 암호화 미설정
                findings.append({
                    "CheckID": self.id,
                    "Result": "FAIL",
                    "ObjectType": "Pod",
                    "ObjectName": pod_name,
                    "Namespace": "kube-system",
                    "Reason": "--encryption-provider-config 플래그가 설정되지 않음 (etcd 데이터 암호화 미적용)",
                    "Evidence": {"args": args_list},
                    "Remediation": (
                        "kube-apiserver 매니페스트에 --encryption-provider-config 플래그를 추가하고 "
                        "암호화 설정 파일 경로를 지정하세요. 암호화 방식은 aescbc 이상을 사용해야 합니다. "
                        "예: --encryption-provider-config=/etc/kubernetes/encryption-config.yaml"
                    )
                })
            else:
                # 플래그가 있음 -> 설정 파일 경로 확인 및 내용 분석 시도
                config_analysis = self._check_encryption_config_from_pod(spec, encryption_config)
                
                if config_analysis:
                    if config_analysis.get("status") == "safe":
                        findings.append({
                            "CheckID": self.id,
                            "Result": "PASS",
                            "ObjectType": "Pod",
                            "ObjectName": pod_name,
                            "Namespace": "kube-system",
                            "Reason": f"--encryption-provider-config 설정됨. {config_analysis.get('reason')}",
                            "Evidence": {
                                "args": args_list,
                                "encryption_provider_config_path": encryption_config,
                                "encryption_methods": config_analysis.get("methods", [])
                            },
                            "Remediation": ""
                        })
                    elif config_analysis.get("status") == "unsafe":
                        findings.append({
                            "CheckID": self.id,
                            "Result": "FAIL",
                            "ObjectType": "Pod",
                            "ObjectName": pod_name,
                            "Namespace": "kube-system",
                            "Reason": f"--encryption-provider-config 설정됨. {config_analysis.get('reason')}",
                            "Evidence": {
                                "args": args_list,
                                "encryption_provider_config_path": encryption_config,
                                "encryption_methods": config_analysis.get("methods", [])
                            },
                            "Remediation": (
                                f"암호화 설정 파일({encryption_config})에서 안전한 암호화 방식(aescbc, aesgcm, secretbox, kms)을 사용하도록 수정하세요. "
                                "현재 사용 중인 방식: " + ", ".join(config_analysis.get("methods", []))
                            )
                        })
                    else:
                        # unknown 상태
                        findings.append({
                            "CheckID": self.id,
                            "Result": "WARN",
                            "ObjectType": "Pod",
                            "ObjectName": pod_name,
                            "Namespace": "kube-system",
                            "Reason": f"--encryption-provider-config 설정됨. {config_analysis.get('reason')}",
                            "Evidence": {
                                "args": args_list,
                                "encryption_provider_config_path": encryption_config
                            },
                            "Remediation": (
                                f"컨트롤플레인 노드에서 설정 파일({encryption_config})을 직접 확인하여 "
                                "암호화 방식이 aescbc, aesgcm, secretbox, kms 중 하나로 설정되어 있는지 확인하세요."
                            )
                        })
                else:
                    # 설정 파일 내용을 읽을 수 없음 (파일이 노드에 직접 있거나 접근 불가)
                    findings.append({
                        "CheckID": self.id,
                        "Result": "WARN",
                        "ObjectType": "Pod",
                        "ObjectName": pod_name,
                        "Namespace": "kube-system",
                        "Reason": f"--encryption-provider-config 플래그가 설정되어 있음 (경로: {encryption_config}). 설정 파일 내용 확인 필요 (aescbc 이상의 암호화 방식 사용 여부)",
                        "Evidence": {"args": args_list, "encryption_provider_config_path": encryption_config},
                        "Remediation": (
                            f"컨트롤플레인 노드에서 설정 파일({encryption_config})을 확인하여 "
                            "암호화 방식이 aescbc, aesgcm, secretbox, kms 중 하나로 설정되어 있는지 확인하세요. "
                            "설정 파일 예시:\n"
                            "apiVersion: apiserver.config.k8s.io/v1\n"
                            "kind: EncryptionConfiguration\n"
                            "resources:\n"
                            "  - resources:\n"
                            "    - secrets\n"
                            "    providers:\n"
                            "    - aescbc:\n"
                            "        keys:\n"
                            "        - name: key1\n"
                            "          secret: <base64-encoded-secret>"
                        )
                    })

        return findings

