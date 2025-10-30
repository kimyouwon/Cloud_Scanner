import importlib
import pkgutil
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from kubernetes import config, client
import os
import json
import argparse
import sys

# checks 패키지에서 모든 모듈을 동적 로드
def load_checks():
    import scanner.checks as checks_pkg
    checks = []
    for _, modname, _ in pkgutil.iter_modules(checks_pkg.__path__):
        mod = importlib.import_module(f"scanner.checks.{modname}")
        # 모듈 내 클래스들 중 Check를 상속한 클래스 인스턴스 생성
        for attr in dir(mod):
            cls = getattr(mod, attr)
            try:
                from scanner.checks.base import Check
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Security Scanner CLI")
    parser.add_argument("--kubeconfig", type=str, help="Path to kubeconfig file")
    parser.add_argument("--output", type=str, help="Output file path (JSON)")
    parser.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    
    args = parser.parse_args()
    
    # kubeconfig 설정
    if args.kubeconfig:
        os.environ["KUBECONFIG"] = args.kubeconfig
    
    try:
        print("🔍 Kubernetes Security Scanner 시작...", file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        
        # 스캔 실행
        results = run_all_checks(concurrency=6)
        
        # 결과 출력
        if args.format == "json":
            output = json.dumps(results, indent=2, ensure_ascii=False)
            print(output)
        else:
            # 간단한 테이블 형식
            print("\n📊 스캔 결과:", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            for result in results.get("Results", []):
                check_id = result.get("CheckID", "UNKNOWN")
                status = result.get("Result", "UNKNOWN")
                reason = result.get("Reason", "")
                severity = result.get("Severity", "")
                print(f"{check_id}: {status} [{severity}]", file=sys.stderr)
                if reason:
                    print(f"  └─ {reason}", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            # JSON도 출력
            output = json.dumps(results, indent=2, ensure_ascii=False)
            print(output)
        
        # 파일로 저장
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\n✅ 결과가 {args.output}에 저장되었습니다.", file=sys.stderr)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ 오류 발생: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
