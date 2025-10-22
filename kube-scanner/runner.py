import importlib
import pkgutil
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from kubernetes import config, client
import os

# checks 패키지에서 모든 모듈을 동적 로드
def load_checks():
    import checks as checks_pkg
    checks = []
    for _, modname, _ in pkgutil.iter_modules(checks_pkg.__path__):
        mod = importlib.import_module(f"checks.{modname}")
        # 모듈 내 클래스들 중 Check를 상속한 클래스 인스턴스 생성
        for attr in dir(mod):
            cls = getattr(mod, attr)
            try:
                from checks.base import Check
                if isinstance(cls, type) and issubclass(cls, Check) and cls is not Check:
                    checks.append(cls())
            except Exception:
                continue
    return checks

def make_k8s_client():
    # 클러스터 내부에서 동작하면 in_cluster, 개발시에는 kubeconfig 로드
    try:
        if os.getenv("KUBERNETES_SERVICE_HOST"):
            config.load_incluster_config()
        else:
            # dev: ~/.kube/config 사용
            config.load_kube_config()
    except Exception:
        # 마지막 수단: raise 하도록 둠
        raise
    return client

def run_all_checks(concurrency: int = 6):
    k8s_client = make_k8s_client()
    checks = load_checks()
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(c.run, k8s_client): c for c in checks}
        for fut in as_completed(futures):
            c = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = [{
                    "CheckID": getattr(c, "id", "UNKNOWN"),
                    "Result": "ERROR",
                    "Reason": str(e)
                }]
            # res는 리스트 형태(각 체크가 여러 finding 반환 가능)
            if isinstance(res, list):
                results.extend(res)
            else:
                results.append(res)
    payload = {
        "ScanID": f"scan-{os.urandom(4).hex()}",
        "Timestamp": __import__("datetime").datetime.now().__str__(),
        "Results": results
    }
    return payload
