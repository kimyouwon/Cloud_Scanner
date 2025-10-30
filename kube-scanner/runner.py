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

def calculate_score(results: List[Dict], total_checks: int) -> Dict:
    """스캔 결과로부터 점수를 계산합니다."""
    if total_checks == 0:
        return {"score": 0, "max_score": 0, "percentage": 0}
    
    # 각 체크당 1점 (총 100점 만점)
    points_per_check = 100.0 / total_checks
    earned_points = 0
    failed_count = 0
    error_count = 0
    pass_count = 0
    
    for result in results:
        status = result.get("Result", "UNKNOWN")
        if status == "PASS":
            earned_points += points_per_check
            pass_count += 1
        elif status == "FAIL":
            failed_count += 1
        elif status == "ERROR":
            error_count += 1
    
    return {
        "score": round(earned_points, 2),
        "max_score": 100.0,
        "percentage": round(earned_points, 1),
        "passed": pass_count,
        "failed": failed_count,
        "error": error_count,
        "total": total_checks
    }

def print_summary(results: List[Dict], checks_count: int):
    """스캔 결과 요약을 출력합니다."""
    score_info = calculate_score(results, checks_count)
    
    print("\n" + "=" * 50, file=sys.stderr)
    print("Scan Results Summary", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(f"Total Checks: {checks_count}", file=sys.stderr)
    print(f"Passed: {score_info['passed']}", file=sys.stderr)
    print(f"Failed: {score_info['failed']}", file=sys.stderr)
    if score_info['error'] > 0:
        print(f"Errors: {score_info['error']}", file=sys.stderr)
    print("-" * 50, file=sys.stderr)
    print(f"Security Score: {score_info['percentage']}/100", file=sys.stderr)
    
    # 점수에 따른 등급
    if score_info['percentage'] == 100:
        grade = "Perfect"
    elif score_info['percentage'] >= 80:
        grade = "Good"
    elif score_info['percentage'] >= 60:
        grade = "Fair"
    else:
        grade = "Poor - Needs Improvement"
    
    print(f"Grade: {grade}", file=sys.stderr)
    print("=" * 50 + "\n", file=sys.stderr)

def run_all_checks(concurrency: int = 6, kubeconfig: str = ''):
    checks = load_checks()
    results = []
    
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {}
        for c in checks:
            # 체크 타입에 따라 다른 파라미터 전달
            try:
                import inspect
                sig = inspect.signature(c.run)
                params = sig.parameters
                
                # k8s_client가 필요하면 클라이언트 생성
                if 'k8s_client' in params:
                    k8s_client = make_k8s_client()
                    futures[ex.submit(c.run, k8s_client)] = c
                elif 'kubeconfig' in params:
                    futures[ex.submit(c.run, kubeconfig)] = c
                else:
                    # 파라미터 없으면 그냥 실행
                    futures[ex.submit(c.run)] = c
            except Exception as e:
                # 체크 로드 실패는 무시하고 계속
                continue
        
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
    
    # 체크당 1개의 결과만 사용 (중복 제거)
    unique_results = {}
    for result in results:
        check_id = result.get("CheckID", "UNKNOWN")
        # 같은 CheckID가 여러 번 나올 수 있으므로 FAIL > ERROR > PASS 우선순위
        if check_id not in unique_results:
            unique_results[check_id] = result
        else:
            existing = unique_results[check_id]
            existing_status = existing.get("Result", "")
            current_status = result.get("Result", "")
            # FAIL이면 무조건 FAIL 유지, ERROR면 FAIL이면 교체
            if current_status == "FAIL" or (current_status == "ERROR" and existing_status == "PASS"):
                unique_results[check_id] = result
    
    # 고유한 체크 결과만 사용
    unique_results_list = list(unique_results.values())
    
    payload = {
        "ScanID": f"scan-{os.urandom(4).hex()}",
        "Timestamp": __import__("datetime").datetime.now().__str__(),
        "Results": unique_results_list,
        "Summary": calculate_score(unique_results_list, len(checks))
    }
    return payload

def save_human_readable(results: Dict, output_path: str):
    """결과를 사람이 읽기 쉬운 형식으로 저장합니다."""
    ext = os.path.splitext(output_path)[1].lower()
    
    if ext == '.md':
        save_markdown(results, output_path)
    else:
        save_text(results, output_path)

def save_text(results: Dict, output_path: str):
    """텍스트 형식으로 저장합니다."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("Kubernetes Security Scanner Results\n")
        f.write("=" * 80 + "\n\n")
        
        # Summary
        summary = results.get("Summary", {})
        f.write("SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Scan ID: {results.get('ScanID', 'N/A')}\n")
        f.write(f"Timestamp: {results.get('Timestamp', 'N/A')}\n")
        f.write(f"Total Checks: {summary.get('total', 0)}\n")
        f.write(f"Passed: {summary.get('passed', 0)}\n")
        f.write(f"Failed: {summary.get('failed', 0)}\n")
        if summary.get('error', 0) > 0:
            f.write(f"Errors: {summary.get('error', 0)}\n")
        f.write(f"Security Score: {summary.get('percentage', 0)}/100\n")
        
        # Grade
        percentage = summary.get('percentage', 0)
        if percentage == 100:
            grade = "Perfect"
        elif percentage >= 80:
            grade = "Good"
        elif percentage >= 60:
            grade = "Fair"
        else:
            grade = "Poor - Needs Improvement"
        f.write(f"Grade: {grade}\n\n")
        
        # Results
        f.write("DETAILED RESULTS\n")
        f.write("-" * 80 + "\n\n")
        
        for result in results.get("Results", []):
            check_id = result.get("CheckID", "UNKNOWN")
            status = result.get("Result", "UNKNOWN")
            reason = result.get("Reason", "")
            severity = result.get("Severity", "")
            obj_type = result.get("ObjectType", "")
            obj_name = result.get("ObjectName", "")
            namespace = result.get("Namespace", "")
            remediation = result.get("Remediation", "")
            
            f.write(f"{check_id}: {status} [{severity}]\n")
            if reason:
                f.write(f"  Reason: {reason}\n")
            if obj_type and obj_name:
                f.write(f"  Resource: {obj_type}/{obj_name}")
                if namespace and namespace != "N/A":
                    f.write(f" (namespace: {namespace})")
                f.write("\n")
            if remediation:
                f.write(f"  Remediation: {remediation}\n")
            f.write("\n")

def save_markdown(results: Dict, output_path: str):
    """마크다운 형식으로 저장합니다."""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# Kubernetes Security Scanner Results\n\n")
        
        # Summary
        summary = results.get("Summary", {})
        f.write("## Summary\n\n")
        f.write(f"- **Scan ID**: `{results.get('ScanID', 'N/A')}`\n")
        f.write(f"- **Timestamp**: {results.get('Timestamp', 'N/A')}\n")
        f.write(f"- **Total Checks**: {summary.get('total', 0)}\n")
        f.write(f"- **Passed**: {summary.get('passed', 0)}\n")
        f.write(f"- **Failed**: {summary.get('failed', 0)}\n")
        if summary.get('error', 0) > 0:
            f.write(f"- **Errors**: {summary.get('error', 0)}\n")
        f.write(f"- **Security Score**: **{summary.get('percentage', 0)}/100**\n\n")
        
        # Grade
        percentage = summary.get('percentage', 0)
        if percentage == 100:
            grade = "Perfect"
        elif percentage >= 80:
            grade = "Good"
        elif percentage >= 60:
            grade = "Fair"
        else:
            grade = "Poor - Needs Improvement"
        f.write(f"**Grade**: {grade}\n\n")
        
        # Results Table
        f.write("## Detailed Results\n\n")
        f.write("| Check ID | Result | Severity | Resource | Namespace |\n")
        f.write("|----------|--------|----------|----------|-----------|\n")
        
        for result in results.get("Results", []):
            check_id = result.get("CheckID", "UNKNOWN")
            status = result.get("Result", "UNKNOWN")
            severity = result.get("Severity", "")
            obj_type = result.get("ObjectType", "")
            obj_name = result.get("ObjectName", "")
            namespace = result.get("Namespace", "")
            
            # Format resource
            resource = f"{obj_type}/{obj_name}" if obj_type and obj_name else ""
            
            # Status badge
            if status == "PASS":
                status_badge = "✅ PASS"
            elif status == "FAIL":
                status_badge = "❌ FAIL"
            else:
                status_badge = "⚠️ ERROR"
            
            f.write(f"| {check_id} | {status_badge} | {severity} | {resource} | {namespace} |\n")
        
        f.write("\n")
        
        # Detailed findings
        f.write("## Details\n\n")
        for result in results.get("Results", []):
            check_id = result.get("CheckID", "UNKNOWN")
            status = result.get("Result", "UNKNOWN")
            reason = result.get("Reason", "")
            remediation = result.get("Remediation", "")
            
            if status in ["FAIL", "ERROR"] and (reason or remediation):
                f.write(f"### {check_id}\n\n")
                if reason:
                    f.write(f"**Issue**: {reason}\n\n")
                if remediation:
                    f.write(f"**Remediation**: {remediation}\n\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Security Scanner CLI")
    parser.add_argument("--kubeconfig", type=str, help="Path to kubeconfig file")
    parser.add_argument("--output", type=str, help="Output file path (supports .json, .txt, .md)")
    parser.add_argument("--format", choices=["json", "table"], default="json", help="Output format")
    parser.add_argument("--context", type=str, help="Kubernetes context name (default: current context)")
    
    args = parser.parse_args()
    
    # kubeconfig 경로 설정
    kubeconfig_path = ''
    if args.kubeconfig:
        kubeconfig_path = args.kubeconfig
        os.environ["KUBECONFIG"] = args.kubeconfig
    
    try:
        print("Starting Kubernetes Security Scanner...", file=sys.stderr)
        print("=" * 50, file=sys.stderr)
        
        # Minikube 클러스터 상태 확인
        import subprocess
        
        # 1) kubectl 설치 확인
        try:
            subprocess.run(['kubectl', 'version', '--client'], 
                         capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[ERROR] kubectl is not installed or cannot be executed", file=sys.stderr)
            print("[INFO] kubectl installation: https://kubernetes.io/docs/tasks/tools/", file=sys.stderr)
            sys.exit(1)
        
        # 2) Kubernetes 클러스터 연결 확인
        try:
            result = subprocess.run(['kubectl', 'cluster-info'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print("[ERROR] Cannot connect to Kubernetes cluster", file=sys.stderr)
                print(f"   Error: {result.stderr.strip()}", file=sys.stderr)
                print("[INFO] Start Minikube: minikube start", file=sys.stderr)
                sys.exit(1)
            print("[OK] Successfully connected to Kubernetes cluster", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[ERROR] Kubernetes cluster response timeout", file=sys.stderr)
            print("[INFO] Check if cluster is running: minikube status", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Error checking cluster connection: {e}", file=sys.stderr)
            sys.exit(1)
        
        # 3) Minikube 컨텍스트 자동 감지
        if not kubeconfig_path and not args.context:
            try:
                result = subprocess.run(['kubectl', 'config', 'current-context'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    context = result.stdout.strip()
                    print(f"[INFO] Current Kubernetes context: {context}", file=sys.stderr)
                    if 'minikube' in context.lower():
                        print("[OK] Minikube environment detected", file=sys.stderr)
            except Exception:
                pass
        
        print("=" * 50, file=sys.stderr)
        
        # 스캔 실행
        results = run_all_checks(concurrency=6, kubeconfig=kubeconfig_path)
        
        # 체크 수 계산
        checks_count = len([c for c in load_checks()])
        
        # 결과 출력
        if args.format == "json":
            output = json.dumps(results, indent=2, ensure_ascii=False)
            print(output)
        else:
            # 테이블 형식
            print("\nScan Results:", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            for result in results.get("Results", []):
                check_id = result.get("CheckID", "UNKNOWN")
                status = result.get("Result", "UNKNOWN")
                reason = result.get("Reason", "")
                severity = result.get("Severity", "")
                print(f"{check_id}: {status} [{severity}]", file=sys.stderr)
                if reason:
                    print(f"  - {reason}", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            
            # 요약 출력
            print_summary(results.get("Results", []), checks_count)
            
            # JSON도 출력
            output = json.dumps(results, indent=2, ensure_ascii=False)
            print(output)
        
        # 파일로 저장
        if args.output:
            ext = os.path.splitext(args.output)[1].lower()
            if ext in ['.txt', '.md']:
                save_human_readable(results, args.output)
                print(f"\n[OK] Results saved to {args.output}", file=sys.stderr)
            else:
                # JSON 형식으로 저장
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"\n[OK] Results saved to {args.output}", file=sys.stderr)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"[ERROR] Error occurred: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
