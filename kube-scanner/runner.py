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

def calculate_score(results: List[Dict], checks: List) -> Dict:
    """스캔 결과로부터 점수를 계산합니다. 각 체크의 points 속성을 사용합니다."""
    if not checks:
        return {"score": 0, "max_score": 0, "percentage": 0, "passed": 0, "failed": 0, "error": 0, "total": 0}
    
    # 체크 ID별 점수 매핑 생성
    check_points = {}
    total_max_points = 0
    for check in checks:
        check_id = getattr(check, "id", "UNKNOWN")
        points = getattr(check, "points", 0)
        check_points[check_id] = points
        total_max_points += points
    
    if total_max_points == 0:
        return {"score": 0, "max_score": 0, "percentage": 0, "passed": 0, "failed": 0, "error": 0, "total": len(checks)}
    
    earned_points = 0
    failed_count = 0
    error_count = 0
    pass_count = 0
    
    # 결과별로 점수 계산
    for result in results:
        check_id = result.get("CheckID", "UNKNOWN")
        status = result.get("Result", "UNKNOWN")
        points = check_points.get(check_id, 0)
        
        if status == "PASS":
            earned_points += points
            pass_count += 1
        elif status == "FAIL":
            failed_count += 1
        elif status == "ERROR":
            error_count += 1
    
    percentage = (earned_points / total_max_points * 100) if total_max_points > 0 else 0
    
    return {
        "score": round(earned_points, 2),
        "max_score": total_max_points,
        "percentage": round(percentage, 1),
        "passed": pass_count,
        "failed": failed_count,
        "error": error_count,
        "total": len(checks)
    }

def print_summary(results: List[Dict], checks: List):
    """스캔 결과 요약을 출력합니다."""
    score_info = calculate_score(results, checks)
    
    print("\n" + "=" * 50, file=sys.stderr)
    print("Scan Results Summary", file=sys.stderr)
    print("=" * 50, file=sys.stderr)
    print(f"Total Checks: {score_info['total']}", file=sys.stderr)
    print(f"Passed: {score_info['passed']}", file=sys.stderr)
    print(f"Failed: {score_info['failed']}", file=sys.stderr)
    if score_info['error'] > 0:
        print(f"Errors: {score_info['error']}", file=sys.stderr)
    print("-" * 50, file=sys.stderr)
    print(f"Security Score: {score_info['score']}/{score_info['max_score']} ({score_info['percentage']}%)", file=sys.stderr)
    
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
        "Summary": calculate_score(unique_results_list, checks)
    }
    return payload

def save_human_readable(results: Dict, output_path: str):
    """결과를 사람이 읽기 쉬운 형식으로 저장합니다."""
    ext = os.path.splitext(output_path)[1].lower()
    
    if ext == '.html':
        save_html(results, output_path)
    elif ext == '.md':
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
        f.write(f"Security Score: {summary.get('score', 0)}/{summary.get('max_score', 100)} ({summary.get('percentage', 0)}%)\n")
        
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
        f.write(f"- **Security Score**: **{summary.get('score', 0)}/{summary.get('max_score', 100)} ({summary.get('percentage', 0)}%)**\n\n")
        
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

def save_html(results: Dict, output_path: str):
    """HTML 형식으로 저장합니다."""
    # 체크 목록 로드하여 이름과 점수 정보 가져오기
    checks_list = load_checks()
    check_info = {}
    for check in checks_list:
        check_id = getattr(check, "id", "UNKNOWN")
        check_name = getattr(check, "name", check_id)
        check_points = getattr(check, "points", 0)
        check_info[check_id] = {"name": check_name, "points": check_points}
    
    summary = results.get("Summary", {})
    percentage = summary.get('percentage', 0)
    passed = summary.get('passed', 0)
    failed = summary.get('failed', 0)
    error_count = summary.get('error', 0)
    total = summary.get('total', 0)
    
    # Grade 결정 (한국어)
    if percentage == 100:
        grade = "양호"
        grade_color = "#10b981"  # green
    elif percentage >= 80:
        grade = "양호"
        grade_color = "#10b981"  # green
    elif percentage >= 60:
        grade = "주의"
        grade_color = "#f59e0b"  # amber
    else:
        grade = "심각"
        grade_color = "#ef4444"  # red
    
    # Status별 색상
    def get_status_color(status):
        if status == "PASS":
            return "#10b981"
        elif status == "FAIL":
            return "#ef4444"
        elif status == "WARN":
            return "#f59e0b"
        else:
            return "#6b7280"
    
    def get_status_badge(status):
        if status == "PASS":
            return '<span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;background:#d1fae5;color:#065f46;">PASS</span>'
        elif status == "FAIL":
            return '<span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;background:#fee2e2;color:#991b1b;">FAIL</span>'
        elif status == "WARN":
            return '<span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;background:#fef3c7;color:#92400e;">WARN</span>'
        else:
            return '<span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:0.75rem;font-weight:600;background:#f3f4f6;color:#374151;">ERROR</span>'
    
    # 점검 대상 정보 가져오기
    import subprocess
    target_name = "Kubernetes Cluster"
    try:
        result = subprocess.run(['kubectl', 'config', 'current-context'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            target_name = result.stdout.strip()
    except:
        pass
    
    # 점검 일시 포맷팅
    from datetime import datetime
    try:
        scan_time = datetime.fromisoformat(results.get('Timestamp', '').replace(' ', 'T').split('.')[0])
        formatted_time = scan_time.strftime('%Y-%m-%d %H:%M:%S')
    except:
        formatted_time = results.get('Timestamp', 'N/A')
    
    # 결과 분류
    pass_results = [r for r in results.get("Results", []) if r.get("Result") == "PASS"]
    fail_results = [r for r in results.get("Results", []) if r.get("Result") == "FAIL"]
    warn_results = [r for r in results.get("Results", []) if r.get("Result") == "WARN"]
    error_results = [r for r in results.get("Results", []) if r.get("Result") == "ERROR"]
    
    # 심각도별 분포 계산
    severity_data = {}
    for result in results.get("Results", []):
        severity = result.get("Severity", "N/A")
        status = result.get("Result", "UNKNOWN")
        if severity not in severity_data:
            severity_data[severity] = {"pass": 0, "fail": 0, "warn": 0, "error": 0}
        if status == "PASS":
            severity_data[severity]["pass"] += 1
        elif status == "FAIL":
            severity_data[severity]["fail"] += 1
        elif status == "WARN":
            severity_data[severity]["warn"] += 1
        else:
            severity_data[severity]["error"] += 1
    
    severity_labels = list(severity_data.keys()) if severity_data else ["N/A"]
    
    # SVG 차트 생성 함수
    import math
    
    def create_donut_chart(passed, failed, warn, error, total, size=200):
        """도넛 차트 SVG 생성"""
        if total == 0:
            return '<div style="text-align:center;padding:40px;">데이터 없음</div>'
        
        center = size / 2
        radius = size / 2 - 20
        stroke_width = 30
        
        # 각도 계산
        def get_angle(value):
            return (value / total) * 360
        
        def get_coords(angle, r):
            rad = math.radians(angle - 90)
            x = center + r * math.cos(rad)
            y = center + r * math.sin(rad)
            return x, y
        
        colors = {
            'pass': '#10b981',
            'fail': '#ef4444',
            'warn': '#f59e0b',
            'error': '#6b7280'
        }
        
        paths = []
        current_angle = 0
        
        if passed > 0:
            angle = get_angle(passed)
            x1, y1 = get_coords(current_angle, radius)
            x2, y2 = get_coords(current_angle + angle, radius)
            large_arc = 1 if angle > 180 else 0
            paths.append(f'<path d="M {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2}" '
                        f'stroke="{colors["pass"]}" stroke-width="{stroke_width}" fill="none" />')
            current_angle += angle
        
        if failed > 0:
            angle = get_angle(failed)
            x1, y1 = get_coords(current_angle, radius)
            x2, y2 = get_coords(current_angle + angle, radius)
            large_arc = 1 if angle > 180 else 0
            paths.append(f'<path d="M {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2}" '
                        f'stroke="{colors["fail"]}" stroke-width="{stroke_width}" fill="none" />')
            current_angle += angle
        
        if warn > 0:
            angle = get_angle(warn)
            x1, y1 = get_coords(current_angle, radius)
            x2, y2 = get_coords(current_angle + angle, radius)
            large_arc = 1 if angle > 180 else 0
            paths.append(f'<path d="M {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2}" '
                        f'stroke="{colors["warn"]}" stroke-width="{stroke_width}" fill="none" />')
            current_angle += angle
        
        if error > 0:
            angle = get_angle(error)
            x1, y1 = get_coords(current_angle, radius)
            x2, y2 = get_coords(current_angle + angle, radius)
            large_arc = 1 if angle > 180 else 0
            paths.append(f'<path d="M {x1} {y1} A {radius} {radius} 0 {large_arc} 1 {x2} {y2}" '
                        f'stroke="{colors["error"]}" stroke-width="{stroke_width}" fill="none" />')
        
        return f'''
        <svg width="{size}" height="{size}" style="display:block;margin:0 auto;">
            {''.join(paths)}
            <circle cx="{center}" cy="{center}" r="{radius - stroke_width/2}" fill="white" />
            <text x="{center}" y="{center - 10}" text-anchor="middle" font-size="24" font-weight="bold" fill="#1f2937">{total}</text>
            <text x="{center}" y="{center + 15}" text-anchor="middle" font-size="14" fill="#6b7280">전체</text>
        </svg>
        '''
    
    def create_bar_chart(severity_data, severity_labels, width=300, height=200):
        """막대 그래프 SVG 생성"""
        if not severity_data or not severity_labels:
            return '<div style="text-align:center;padding:40px;">데이터 없음</div>'
        
        padding = 40
        chart_width = width - padding * 2
        chart_height = height - padding * 2
        bar_width = chart_width / (len(severity_labels) * 4 + 1)
        max_value = max(
            max(severity_data.get(s, {}).get('pass', 0) for s in severity_labels),
            max(severity_data.get(s, {}).get('fail', 0) for s in severity_labels),
            max(severity_data.get(s, {}).get('warn', 0) for s in severity_labels),
            max(severity_data.get(s, {}).get('error', 0) for s in severity_labels),
            1
        )
        
        bars = []
        labels = []
        colors = {'pass': '#10b981', 'fail': '#ef4444', 'warn': '#f59e0b', 'error': '#6b7280'}
        
        for i, label in enumerate(severity_labels):
            x = padding + (i * 4 + 1) * bar_width
            data = severity_data.get(label, {})
            y_base = padding + chart_height
            
            # 각 상태별 막대
            for j, (status, color) in enumerate([('pass', colors['pass']), ('fail', colors['fail']), 
                                                  ('warn', colors['warn']), ('error', colors['error'])]):
                value = data.get(status, 0)
                if value > 0:
                    bar_height = (value / max_value) * chart_height
                    y = y_base - bar_height
                    bars.append(f'<rect x="{x + j * bar_width}" y="{y}" width="{bar_width * 0.8}" '
                              f'height="{bar_height}" fill="{color}" />')
            
            labels.append(f'<text x="{x + bar_width * 2}" y="{height - 10}" text-anchor="middle" '
                         f'font-size="10" fill="#374151">{label[:8]}</text>')
        
        return f'''
        <svg width="{width}" height="{height}" style="display:block;margin:0 auto;">
            {''.join(bars)}
            {''.join(labels)}
        </svg>
        '''
    
    donut_chart_svg = create_donut_chart(passed, failed, len(warn_results), error_count, total)
    bar_chart_svg = create_bar_chart(severity_data, severity_labels)
    
    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Security Scanner Results</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #1f2937;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: #f9fafb;
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            border: 2px solid #e5e7eb;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
        }}
        
        .summary-card .label {{
            font-size: 0.875rem;
            color: #6b7280;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        
        .summary-card .value {{
            font-size: 2rem;
            font-weight: 700;
            color: #1f2937;
        }}
        
        .score-card {{
            background: linear-gradient(135deg, {grade_color}15 0%, {grade_color}05 100%);
            border: 2px solid {grade_color};
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            margin-bottom: 40px;
        }}
        
        .score-card .score-label {{
            font-size: 1.125rem;
            color: #6b7280;
            margin-bottom: 12px;
        }}
        
        .score-card .score-value {{
            font-size: 3.5rem;
            font-weight: 700;
            color: {grade_color};
            margin-bottom: 8px;
        }}
        
        .score-card .grade {{
            font-size: 1.5rem;
            font-weight: 600;
            color: {grade_color};
        }}
        
        .info-section {{
            background: #f9fafb;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 40px;
        }}
        
        .info-section .info-item {{
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .info-section .info-item:last-child {{
            border-bottom: none;
        }}
        
        .info-section .info-label {{
            font-weight: 600;
            color: #374151;
        }}
        
        .info-section .info-value {{
            color: #6b7280;
            font-family: 'Courier New', monospace;
        }}
        
        .results-section h2 {{
            font-size: 1.875rem;
            margin-bottom: 24px;
            color: #1f2937;
        }}
        
        .results-table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            margin-bottom: 40px;
        }}
        
        .results-table thead {{
            background: #f3f4f6;
        }}
        
        .results-table th {{
            padding: 16px;
            text-align: left;
            font-weight: 600;
            color: #374151;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .results-table td {{
            padding: 16px;
            border-top: 1px solid #e5e7eb;
        }}
        
        .results-table tbody tr:hover {{
            background: #f9fafb;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .badge-pass {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .badge-fail {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .badge-warn {{
            background: #fef3c7;
            color: #92400e;
        }}
        
        .badge-error {{
            background: #f3f4f6;
            color: #374151;
        }}
        
        .details-section {{
            margin-top: 40px;
        }}
        
        .detail-card {{
            background: #f9fafb;
            border-left: 4px solid #ef4444;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        
        .detail-card.pass {{
            border-left-color: #10b981;
        }}
        
        .detail-card h3 {{
            font-size: 1.25rem;
            margin-bottom: 16px;
            color: #1f2937;
        }}
        
        .detail-card .reason {{
            background: white;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 16px;
            color: #374151;
            line-height: 1.6;
        }}
        
        .detail-card .remediation {{
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 16px;
            border-radius: 8px;
            color: #1e40af;
            line-height: 1.6;
        }}
        
        .detail-card .remediation strong {{
            display: block;
            margin-bottom: 8px;
            color: #1e3a8a;
        }}
        
        .footer {{
            background: #f9fafb;
            padding: 24px;
            text-align: center;
            color: #6b7280;
            font-size: 0.875rem;
        }}
        
        .charts-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }}
        
        .chart-container {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        
        .chart-container h3 {{
            font-size: 1.125rem;
            color: #374151;
            margin-bottom: 16px;
            text-align: center;
        }}
        
        .progress-bar-container {{
            background: #f3f4f6;
            border-radius: 12px;
            height: 32px;
            overflow: hidden;
            margin-bottom: 40px;
            position: relative;
        }}
        
        .progress-bar {{
            height: 100%;
            background: linear-gradient(90deg, {grade_color} 0%, {grade_color}dd 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
            font-size: 0.875rem;
            transition: width 1s ease-in-out;
            width: {percentage}%;
        }}
        
        .progress-bar-text {{
            position: absolute;
            width: 100%;
            text-align: center;
            line-height: 32px;
            color: #374151;
            font-weight: 600;
            z-index: 1;
        }}
        
        .filter-buttons {{
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }}
        
        .filter-btn {{
            padding: 8px 16px;
            border: 2px solid #e5e7eb;
            background: white;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.2s;
        }}
        
        .filter-btn:hover {{
            border-color: #667eea;
            background: #f9fafb;
        }}
        
        .filter-btn.active {{
            background: #667eea;
            color: white;
            border-color: #667eea;
        }}
        
        .hidden {{
            display: none;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.75rem;
            }}
            
            .summary-section {{
                grid-template-columns: 1fr;
            }}
            
            .results-table {{
                font-size: 0.875rem;
            }}
            
            .results-table th,
            .results-table td {{
                padding: 12px 8px;
            }}
        }}
    </style>
</head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:#e0f2fe;min-height:100vh;color:#1f2937;">
    <div class="container" style="max-width:1200px;margin:20px auto;background:white;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.1);overflow:hidden;">
        <div style="background:white;padding:30px;">
            <h1 style="font-size:1.5rem;font-weight:600;margin:0 0 30px 0;color:#1f2937;">[보안 점검 리포트]</h1>
            
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:30px;gap:30px;">
                <!-- 왼쪽: 점검 정보 -->
                <div style="flex:1;">
                    <div style="margin-bottom:12px;">
                        <span style="font-weight:600;color:#374151;">점검 대상:</span>
                        <span style="color:#6b7280;margin-left:8px;">{target_name}</span>
                    </div>
                    <div style="margin-bottom:12px;">
                        <span style="font-weight:600;color:#374151;">점검 일시:</span>
                        <span style="color:#6b7280;margin-left:8px;">{formatted_time}</span>
                    </div>
                    <div style="margin-bottom:12px;">
                        <span style="font-weight:600;color:#374151;">총 항목수:</span>
                        <span style="color:#6b7280;margin-left:8px;">{total}</span>
                    </div>
                    <div style="margin-bottom:12px;">
                        <span style="font-weight:600;color:#374151;">FAIL 항목 수:</span>
                        <span style="color:#ef4444;margin-left:8px;font-weight:600;">{failed}</span>
                    </div>
                </div>
                
                <!-- 오른쪽: 점수 및 등급 -->
                <div style="display:flex;align-items:center;gap:20px;">
                    <div style="background:{grade_color};color:white;padding:12px 24px;border-radius:8px;font-weight:600;font-size:1.125rem;">
                        {grade}
                    </div>
                    <div>
                        <div style="font-size:2.5rem;font-weight:700;color:#1f2937;line-height:1;">
                            {int(summary.get('score', 0))}점
                        </div>
                        <div style="font-size:0.875rem;color:#6b7280;margin-top:4px;">
                            스캔 점수
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 상세 결과 테이블 -->
            <div style="margin-top:30px;">
                <table id="resultsTable" style="width:100%;border-collapse:collapse;background:white;border:1px solid #e5e7eb;">
                    <thead style="background:#f3f4f6;">
                        <tr>
                            <th style="padding:12px;text-align:left;font-weight:600;color:#374151;font-size:0.875rem;border-bottom:2px solid #e5e7eb;">항목</th>
                            <th style="padding:12px;text-align:left;font-weight:600;color:#374151;font-size:0.875rem;border-bottom:2px solid #e5e7eb;">대상</th>
                            <th style="padding:12px;text-align:left;font-weight:600;color:#374151;font-size:0.875rem;border-bottom:2px solid #e5e7eb;">결과</th>
                            <th style="padding:12px;text-align:left;font-weight:600;color:#374151;font-size:0.875rem;border-bottom:2px solid #e5e7eb;">점수</th>
                        </tr>
                    </thead>
                    <tbody>
"""
    
    # 테이블 행 추가
    for result in results.get("Results", []):
        check_id = result.get("CheckID", "UNKNOWN")
        status = result.get("Result", "UNKNOWN")
        obj_type = result.get("ObjectType", "")
        obj_name = result.get("ObjectName", "")
        namespace = result.get("Namespace", "")
        
        # 체크 이름 가져오기
        check_name = check_info.get(check_id, {}).get("name", check_id)
        check_points = check_info.get(check_id, {}).get("points", 0)
        
        # 대상 정보 구성
        if namespace and namespace != "N/A" and obj_name:
            target = f"{namespace}/{obj_name}"
        elif obj_name:
            target = obj_name
        elif obj_type:
            target = obj_type
        else:
            target = "-"
        
        # 점수 계산 (FAIL이면 -points, PASS면 -)
        if status == "FAIL":
            score_display = f"-{int(check_points)}" if check_points > 0 else "-"
        else:
            score_display = "-"
        
        # 결과 색상
        result_color = "#ef4444" if status == "FAIL" else "#1f2937"
        
        html += f"""
                        <tr data-status="{status}" style="border-top:1px solid #e5e7eb;">
                            <td style="padding:12px;color:#1f2937;">{check_name}</td>
                            <td style="padding:12px;color:#6b7280;">{target}</td>
                            <td style="padding:12px;color:{result_color};font-weight:600;">{status}</td>
                            <td style="padding:12px;color:#6b7280;">{score_display}</td>
                        </tr>
"""
    
    html += """
                    </tbody>
                </table>
            </div>
"""
    
    # FAIL 항목이 있으면 경고 메시지 추가
    if failed > 0:
        html += f"""
            <div style="margin-top:20px;padding:16px;background:#fef2f2;border-left:4px solid #ef4444;border-radius:4px;">
                <div style="font-weight:600;color:#991b1b;margin-bottom:8px;">주의! FAIL 항목 {failed}건 발견</div>
                <div style="color:#6b7280;font-size:0.875rem;">보안 권고:</div>
            </div>
"""
    
    html += """
            </div>
        </div>
        
        <div style="background:#f9fafb;padding:20px;text-align:center;color:#6b7280;font-size:0.875rem;margin-top:20px;">
            <p style="margin:0;">Generated by Kubernetes Security Scanner</p>
        </div>
    </div>
    
    <script>
        // 테이블 행 호버 효과
        document.addEventListener('DOMContentLoaded', function() {
            const rows = document.querySelectorAll('#resultsTable tbody tr');
            rows.forEach(row => {
                row.addEventListener('mouseenter', function() {
                    this.style.backgroundColor = '#f9fafb';
                });
                row.addEventListener('mouseleave', function() {
                    this.style.backgroundColor = 'white';
                });
            });
        });
    </script>
</body>
</html>
    """
    
    # HTML 파일 저장 (BOM 없이 UTF-8)
    try:
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            f.write(html)
        
        # 파일이 제대로 생성되었는지 확인
        import os
        if os.path.exists(output_path):
            file_size = os.path.getsize(output_path)
            if file_size == 0:
                raise Exception(f"HTML 파일이 비어있습니다: {output_path}")
            # HTML 시작 부분 확인
            with open(output_path, 'r', encoding='utf-8') as check_file:
                first_line = check_file.readline()
                if not first_line.strip().startswith('<!DOCTYPE'):
                    # HTML이 제대로 생성되지 않았으면 다시 시도
                    print(f"[WARN] HTML 파일 형식 확인 실패, 재생성 시도...", file=sys.stderr)
                    # 간단한 HTML로 재생성
                    simple_html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Security Scanner Results</title>
</head>
<body style="margin:0;padding:20px;font-family:Arial,sans-serif;background:#e0f2fe;">
    <div style="max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px;">
        <h1 style="font-size:1.5rem;margin-bottom:30px;">[보안 점검 리포트]</h1>
        <div style="display:flex;justify-content:space-between;margin-bottom:30px;">
            <div>
                <div style="margin-bottom:12px;"><strong>점검 대상:</strong> {target_name}</div>
                <div style="margin-bottom:12px;"><strong>점검 일시:</strong> {formatted_time}</div>
                <div style="margin-bottom:12px;"><strong>총 항목수:</strong> {total}</div>
                <div style="margin-bottom:12px;"><strong>FAIL 항목 수:</strong> <span style="color:#ef4444;">{failed}</span></div>
            </div>
            <div style="display:flex;align-items:center;gap:20px;">
                <div style="background:{grade_color};color:white;padding:12px 24px;border-radius:8px;font-weight:600;">{grade}</div>
                <div>
                    <div style="font-size:2.5rem;font-weight:700;">{int(summary.get('score', 0))}점</div>
                    <div style="font-size:0.875rem;color:#6b7280;">스캔 점수</div>
                </div>
            </div>
        </div>
        <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;">
            <thead style="background:#f3f4f6;">
                <tr>
                    <th style="padding:12px;text-align:left;border-bottom:2px solid #e5e7eb;">항목</th>
                    <th style="padding:12px;text-align:left;border-bottom:2px solid #e5e7eb;">대상</th>
                    <th style="padding:12px;text-align:left;border-bottom:2px solid #e5e7eb;">결과</th>
                    <th style="padding:12px;text-align:left;border-bottom:2px solid #e5e7eb;">점수</th>
                </tr>
            </thead>
            <tbody>
"""
            for result in results.get("Results", []):
                check_id = result.get("CheckID", "UNKNOWN")
                status = result.get("Result", "UNKNOWN")
                obj_name = result.get("ObjectName", "")
                namespace = result.get("Namespace", "")
                check_name = check_info.get(check_id, {}).get("name", check_id)
                check_points = check_info.get(check_id, {}).get("points", 0)
                target = f"{namespace}/{obj_name}" if namespace and namespace != "N/A" and obj_name else (obj_name if obj_name else "-")
                score_display = f"-{int(check_points)}" if status == "FAIL" and check_points > 0 else "-"
                result_color = "#ef4444" if status == "FAIL" else "#1f2937"
                simple_html += f"""
                <tr style="border-top:1px solid #e5e7eb;">
                    <td style="padding:12px;">{check_name}</td>
                    <td style="padding:12px;">{target}</td>
                    <td style="padding:12px;color:{result_color};font-weight:600;">{status}</td>
                    <td style="padding:12px;">{score_display}</td>
                </tr>
"""
            simple_html += """
            </tbody>
        </table>
"""
            if failed > 0:
                simple_html += f"""
        <div style="margin-top:20px;padding:16px;background:#fef2f2;border-left:4px solid #ef4444;border-radius:4px;">
            <div style="font-weight:600;color:#991b1b;margin-bottom:8px;">주의! FAIL 항목 {failed}건 발견</div>
            <div style="color:#6b7280;font-size:0.875rem;">보안 권고:</div>
        </div>
"""
            simple_html += """
    </div>
</body>
</html>
"""
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                f.write(simple_html)
    except Exception as e:
        print(f"[ERROR] HTML 파일 저장 실패: {e}", file=sys.stderr)
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Security Scanner CLI")
    parser.add_argument("--kubeconfig", type=str, help="Path to kubeconfig file")
    parser.add_argument("--output", type=str, help="Output file path (supports .json, .txt, .md, .html)")
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
        
        # 체크 목록 가져오기
        checks_list = load_checks()
        
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
            print_summary(results.get("Results", []), checks_list)
            
            # JSON도 출력
            output = json.dumps(results, indent=2, ensure_ascii=False)
            print(output)
        
        # 파일로 저장
        if args.output:
            ext = os.path.splitext(args.output)[1].lower()
            if ext in ['.txt', '.md', '.html']:
                save_human_readable(results, args.output)
                print(f"\n[OK] Results saved to {args.output}", file=sys.stderr)
                if ext == '.html':
                    print(f"[INFO] Open {args.output} in your browser to view the report", file=sys.stderr)
            else:
                # JSON 형식으로 저장
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"\n[OK] Results saved to {args.output}", file=sys.stderr)
        else:
            # 자동으로 결과 파일 생성
            from datetime import datetime
            scan_id = results.get('ScanID', 'scan')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # results 디렉토리 생성
            results_dir = 'results'
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
                print(f"[INFO] Created results directory: {results_dir}", file=sys.stderr)
            
            # 파일명 생성
            base_filename = f"{scan_id}_{timestamp}"
            
            # JSON 파일 저장
            json_path = os.path.join(results_dir, f"{base_filename}.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\n[OK] JSON results saved to {json_path}", file=sys.stderr)
            
            # HTML 파일 저장
            html_path = os.path.join(results_dir, f"{base_filename}.html")
            save_html(results, html_path)
            print(f"[OK] HTML report saved to {html_path}", file=sys.stderr)
            print(f"[INFO] Open {html_path} in your browser to view the report", file=sys.stderr)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"[ERROR] Error occurred: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
