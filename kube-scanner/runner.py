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

    # 동일 CheckID에 대해 노드별로 여러 결과가 있을 수 있으므로
    # 점수 계산은 "체크별 최악 상태(FAIL > ERROR > WARN > PASS)"만 반영
    status_rank = {
        "PASS": 1,
        "WARN": 2,
        "FAIL": 3,
        "ERROR": 4,
    }
    worst_status_per_check: Dict[str, str] = {}
    for result in results:
        check_id = result.get("CheckID", "UNKNOWN")
        status = result.get("Result", "UNKNOWN")
        if check_id not in worst_status_per_check:
            worst_status_per_check[check_id] = status
        else:
            prev = worst_status_per_check[check_id]
            if status_rank.get(status, 0) > status_rank.get(prev, 0):
                worst_status_per_check[check_id] = status

    earned_points = 0
    failed_count = 0
    error_count = 0
    pass_count = 0
    warn_count = 0
    
    # 체크별 최악 상태 기준으로 점수 계산
    for check_id, status in worst_status_per_check.items():
        points = check_points.get(check_id, 0)

        if status == "PASS":
            earned_points += points
            pass_count += 1
        elif status == "WARN":
            earned_points += points * 0.5  # WARN은 50% 점수
            warn_count += 1
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
        "warn": warn_count,
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

    # node-scanner DaemonSet이 있으면 한 번만 수집해서 재사용
    node_scanner_data = None
    try:
        from scanner.node_scanner import collect_node_scanner_data
        node_scanner_data = collect_node_scanner_data(kubeconfig=kubeconfig)
    except Exception:
        node_scanner_data = None
    
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {}
        for c in checks:
            # 체크 타입에 따라 다른 파라미터 전달
            try:
                import inspect
                sig = inspect.signature(c.run)
                params = sig.parameters

                kwargs = {}
                if 'k8s_client' in params:
                    kwargs['k8s_client'] = make_k8s_client()
                if 'kubeconfig' in params:
                    kwargs['kubeconfig'] = kubeconfig
                if 'node_scanner_data' in params:
                    kwargs['node_scanner_data'] = node_scanner_data

                if kwargs:
                    futures[ex.submit(c.run, **kwargs)] = c
                else:
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
    
    # 여러 노드에 대한 결과가 있을 수 있으므로,
    # 결과 리스트는 그대로 유지하고 각 결과에 메타데이터만 채운다.
    check_info_map = {check.id: check.get_info() for check in checks}
    for result in results:
        check_id = result.get("CheckID", "UNKNOWN")
        if check_id in check_info_map:
            info = check_info_map[check_id]
            # 권고 정보 추가
            result["Description"] = info.get("description", "")
            result["RiskLevel"] = info.get("risk_level", 0)
            result["RecommendedSetting"] = info.get("recommended_setting", "")
            result["VerificationCommand"] = info.get("verification_command", "")
            result["Category"] = info.get("category", "N/A")
    
    payload = {
        "ScanID": f"scan-{os.urandom(4).hex()}",
        "Timestamp": __import__("datetime").datetime.now().__str__(),
        "Results": results,
        "Summary": calculate_score(results, checks)
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

def get_category_display_name(check_id: str) -> str:
    """Check ID를 기반으로 카테고리 표시 이름 반환"""
    if check_id.startswith("CHK-M-API-"):
        return "API Server"
    elif check_id.startswith("CHK-M-ETCD-"):
        return "etcd"
    elif check_id.startswith("CHK-M-CTRL-"):
        return "Controller Manager"
    elif check_id.startswith("CHK-M-FILE-"):
        return "File"
    elif check_id.startswith("CHK-M-PSA-"):
        return "Pod Security"
    elif check_id.startswith("CHK-W-KUBELET-"):
        return "Kubelet"
    elif check_id.startswith("CHK-W-FILE-"):
        return "File"
    else:
        return "N/A"

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
    warn_count = summary.get('warn', 0)
    error_count = summary.get('error', 0)
    total = summary.get('total', 0)
    score = summary.get('score', 0)
    max_score = summary.get('max_score', 0)
    
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
    
    # HTML 생성 - 모든 스타일을 인라인으로 적용
    html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Security Scanner Results</title>
    <style>
        :root{{
            --bg:#e0f2fe;
            --text:#0f172a;
            --muted:#64748b;
            --border:#e5e7eb;
            --head:#f8fafc;
            --row:#ffffff;
            --rowAlt:#fbfdff;
            --hover:#f1f5f9;
        }}
        *{{box-sizing:border-box}}
        body{{margin:0;padding:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,"Apple SD Gothic Neo","Noto Sans KR",sans-serif;background:var(--bg);min-height:100vh;color:var(--text)}}
        .card{{max-width:1200px;margin:20px auto;background:white;border-radius:14px;box-shadow:0 10px 30px rgba(2,6,23,.10);overflow:hidden;border:1px solid rgba(148,163,184,.35)}}
        .content{{background:white;padding:28px}}
        .title{{font-size:1.4rem;font-weight:750;margin:0 0 22px 0;color:#0f172a;letter-spacing:-.2px}}
        .meta{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:26px;gap:24px}}
        .meta-left{{flex:1}}
        .meta-line{{margin-bottom:10px}}
        .meta-label{{font-weight:700;color:#334155}}
        .meta-value{{color:var(--muted);margin-left:8px}}
        .score-box{{display:flex;align-items:center;gap:18px}}
        .grade{{color:white;padding:10px 16px;border-radius:12px;font-weight:800;font-size:1rem;box-shadow:0 8px 18px rgba(0,0,0,.12)}}
        .score-big{{font-size:2.25rem;font-weight:900;color:#0f172a;line-height:1}}
        .score-sub{{font-size:.875rem;color:var(--muted);margin-top:4px}}
        .table-wrap{{margin-top:18px;border:1px solid var(--border);border-radius:12px;overflow:hidden}}
        table{{width:100%;border-collapse:separate;border-spacing:0;background:white}}
        thead th{{background:var(--head);padding:12px 14px;text-align:left;font-weight:800;color:#334155;font-size:.85rem;border-bottom:1px solid var(--border)}}
        tbody td{{padding:12px 14px;border-bottom:1px solid var(--border);vertical-align:middle}}
        tbody tr:nth-child(odd){{background:var(--row)}}
        tbody tr:nth-child(even){{background:var(--rowAlt)}}
        tbody tr:hover{{background:var(--hover)}}
        .col-category{{color:var(--muted);font-weight:700;white-space:nowrap}}
        .col-item{{color:#0f172a}}
        .col-target{{color:var(--muted)}}
        .badge{{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:.75rem;font-weight:900;letter-spacing:.2px}}
        .badge-pass{{background:#dcfce7;color:#166534}}
        .badge-fail{{background:#fee2e2;color:#991b1b}}
        .badge-warn{{background:#fef3c7;color:#92400e}}
        .badge-error{{background:#f1f5f9;color:#334155}}
        .score-cell{{min-width:120px}}
        .score-pill{{display:inline-flex;flex-direction:column;gap:3px;padding:8px 10px;border-radius:12px;border:1px solid rgba(148,163,184,.45);background:linear-gradient(180deg,#ffffff,#f8fafc);box-shadow:0 1px 0 rgba(2,6,23,.04)}}
        .score-pill-top{{display:flex;align-items:baseline;justify-content:space-between;gap:10px}}
        .score-deduct{{font-weight:900;color:#0f172a}}
        .score-note{{font-size:.72rem;color:var(--muted);font-weight:700}}
    </style>
</head>
<body>
    <div class="card">
        <div class="content">
            <h1 class="title">보안 점검 리포트</h1>
            
            <div class="meta">
                <div class="meta-left">
                    <div class="meta-line"><span class="meta-label">점검 대상</span><span class="meta-value">{target_name}</span></div>
                    <div class="meta-line"><span class="meta-label">점검 일시</span><span class="meta-value">{formatted_time}</span></div>
                    <div class="meta-line"><span class="meta-label">총 항목수</span><span class="meta-value">{total}</span></div>
                    <div class="meta-line"><span class="meta-label">FAIL 항목 수</span><span class="meta-value" style="color:#ef4444;font-weight:900">{failed}</span></div>
                    <div class="meta-line"><span class="meta-label">WARN 항목 수</span><span class="meta-value" style="color:#f59e0b;font-weight:900">{warn_count}</span></div>
                    <div class="meta-line"><span class="meta-label">획득 점수</span><span class="meta-value" style="color:#0f172a;font-weight:900">{int(score)}/{int(max_score)}점</span></div>
                </div>
                <div class="score-box">
                    <div class="grade" style="background:{grade_color};">{grade}</div>
                    <div>
                        <div class="score-big">{int(summary.get('score', 0))}점</div>
                        <div class="score-sub">스캔 점수</div>
                    </div>
                </div>
            </div>
            
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>범주</th>
                            <th>항목</th>
                            <th>대상</th>
                            <th>결과</th>
                            <th style="text-align:right;">점수</th>
                        </tr>
                    </thead>
                    <tbody>
"""
    
    # 테이블 행 추가 (Check ID 순으로 정렬)
    sorted_results = sorted(results.get("Results", []), key=lambda x: x.get("CheckID", "UNKNOWN"))

    # 같은 CheckID가 노드별로 여러 줄 출력되더라도, 점수(감점)는 "체크별 최악 상태" 기준으로 1회만 표시
    status_rank = {"PASS": 1, "WARN": 2, "FAIL": 3, "ERROR": 4}
    group_counts: Dict[str, int] = {}
    worst_status_per_check: Dict[str, str] = {}
    for r in sorted_results:
        cid = r.get("CheckID", "UNKNOWN")
        group_counts[cid] = group_counts.get(cid, 0) + 1
        s = r.get("Result", "UNKNOWN")
        prev = worst_status_per_check.get(cid)
        if prev is None or status_rank.get(s, 0) > status_rank.get(prev, 0):
            worst_status_per_check[cid] = s

    earned_display_per_check: Dict[str, str] = {}
    for cid, worst_status in worst_status_per_check.items():
        pts = check_info.get(cid, {}).get("points", 0)
        if worst_status == "PASS":
            earned = float(pts)
        elif worst_status == "WARN":
            earned = float(pts) * 0.5
        elif worst_status in ("FAIL", "ERROR"):
            earned = 0.0
        else:
            earned = 0.0

        if pts <= 0:
            earned_display_per_check[cid] = "-"
        else:
            # 표시용: 소수점이 없으면 정수로
            earned_str = str(int(earned)) if abs(earned - int(earned)) < 1e-9 else f"{earned:.1f}"
            earned_display_per_check[cid] = f"{earned_str}/{int(pts)}"

    rendered_score_for: set = set()

    for result in sorted_results:
        check_id = result.get("CheckID", "UNKNOWN")
        status = result.get("Result", "UNKNOWN")
        obj_type = result.get("ObjectType", "")
        obj_name = result.get("ObjectName", "")
        namespace = result.get("Namespace", "")
        
        # 체크 이름 및 카테고리 가져오기
        check_name = check_info.get(check_id, {}).get("name", check_id)
        check_points = check_info.get(check_id, {}).get("points", 0)
        check_category = get_category_display_name(check_id)
        
        # 대상 정보 구성
        if namespace and namespace != "N/A" and obj_name:
            target = f"{namespace}/{obj_name}"
        elif obj_name:
            target = obj_name
        elif obj_type:
            target = obj_type
        else:
            target = "-"
        
        # 점수(감점) 표시는 CheckID 기준 1회만 (최악 상태 기준)
        show_score_cell = check_id not in rendered_score_for
        if show_score_cell:
            rendered_score_for.add(check_id)
        score_display = earned_display_per_check.get(check_id, "-")
        
        # 결과 배지 (가독성/일관성)
        if status == "PASS":
            result_badge = '<span class="badge badge-pass">PASS</span>'
        elif status == "FAIL":
            result_badge = '<span class="badge badge-fail">FAIL</span>'
        elif status == "WARN":
            result_badge = '<span class="badge badge-warn">WARN</span>'
        else:
            result_badge = '<span class="badge badge-error">ERROR</span>'

        # 감점 표시는 pill + (체크 기준/최악 결과) 안내
        score_pill_html = (
            f'<span class="score-pill" title="동일 항목(CheckID) 내 여러 대상이 있어도, 점수는 체크별 최악 결과 기준으로 1회만 반영됩니다.">'
            f'  <span class="score-pill-top">'
            f'    <span class="score-deduct">{score_display}</span>'
            f'  </span>'
            f'  <span class="score-note">체크 기준(최악 결과)</span>'
            f'</span>'
        )
        
        html_content += f"""
                        <tr>
                            <td class="col-category">{check_category}</td>
                            <td class="col-item">{check_name}</td>
                            <td class="col-target">{target}</td>
                            <td>{result_badge}</td>
                            {f'<td class="score-cell" rowspan="{group_counts.get(check_id, 1)}" style="text-align:right;vertical-align:middle;">{score_pill_html}</td>' if show_score_cell else ''}
                        </tr>
"""
    
    html_content += """
                    </tbody>
                </table>
            </div>
"""
    
    # FAIL 항목 상세 정보 추가
    fail_items = [r for r in results.get("Results", []) if r.get("Result") == "FAIL"]
    if fail_items:
        html_content += f"""
            <div style="margin-top:30px;">
                <h2 style="color:#991b1b;font-size:1.25rem;margin-bottom:20px;">⚠️ FAIL 항목 상세 정보 ({len(fail_items)}건)</h2>
"""
        for result in fail_items:
            check_id = result.get("CheckID", "UNKNOWN")
            check_name = check_info.get(check_id, {}).get("name", check_id)
            reason = result.get("Reason", "")
            remediation = result.get("Remediation", "")
            recommended_setting = result.get("RecommendedSetting", "")
            verification_command = result.get("VerificationCommand", "")
            description = result.get("Description", "")
            risk_level = result.get("RiskLevel", 0)
            
            html_content += f"""
                <div style="margin-bottom:24px;padding:20px;background:#fef2f2;border-left:4px solid #ef4444;border-radius:4px;">
                    <h3 style="color:#991b1b;font-size:1.1rem;margin-bottom:12px;">{check_id}: {check_name}</h3>
                    {f'<div style="margin-bottom:8px;"><strong>위험도:</strong> <span style="color:#dc2626;">{risk_level}/10</span></div>' if risk_level > 0 else ''}
                    {f'<div style="margin-bottom:8px;"><strong>설명:</strong> {description}</div>' if description else ''}
                    {f'<div style="margin-bottom:8px;"><strong>원인:</strong> <span style="color:#dc2626;">{reason}</span></div>' if reason else ''}
                    {f'<div style="margin-bottom:8px;"><strong>권장 설정:</strong><pre style="background:#f3f4f6;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{recommended_setting}</pre></div>' if recommended_setting else ''}
                    {f'<div style="margin-bottom:8px;"><strong>확인 명령어:</strong><pre style="background:#f3f4f6;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{verification_command}</pre></div>' if verification_command else ''}
                    {f'<div style="margin-top:12px;"><strong>해결 방법:</strong><pre style="background:#f3f4f6;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{remediation}</pre></div>' if remediation else ''}
                </div>
"""
        html_content += """
            </div>
"""
    
    # WARN 항목 상세 정보 추가
    warn_items = [r for r in results.get("Results", []) if r.get("Result") == "WARN"]
    if warn_items:
        html_content += f"""
            <div style="margin-top:30px;">
                <h2 style="color:#92400e;font-size:1.25rem;margin-bottom:20px;">⚠️ WARN 항목 상세 정보 ({len(warn_items)}건)</h2>
"""
        for result in warn_items:
            check_id = result.get("CheckID", "UNKNOWN")
            check_name = check_info.get(check_id, {}).get("name", check_id)
            reason = result.get("Reason", "")
            remediation = result.get("Remediation", "")
            recommended_setting = result.get("RecommendedSetting", "")
            verification_command = result.get("VerificationCommand", "")
            description = result.get("Description", "")
            risk_level = result.get("RiskLevel", 0)
            
            html_content += f"""
                <div style="margin-bottom:24px;padding:20px;background:#fffbeb;border-left:4px solid #f59e0b;border-radius:4px;">
                    <h3 style="color:#92400e;font-size:1.1rem;margin-bottom:12px;">{check_id}: {check_name}</h3>
                    {f'<div style="margin-bottom:8px;"><strong>위험도:</strong> <span style="color:#d97706;">{risk_level}/10</span></div>' if risk_level > 0 else ''}
                    {f'<div style="margin-bottom:8px;"><strong>설명:</strong> {description}</div>' if description else ''}
                    {f'<div style="margin-bottom:8px;"><strong>원인:</strong> <span style="color:#d97706;">{reason}</span></div>' if reason else ''}
                    {f'<div style="margin-bottom:8px;"><strong>권장 설정:</strong><pre style="background:#f3f4f6;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{recommended_setting}</pre></div>' if recommended_setting else ''}
                    {f'<div style="margin-bottom:8px;"><strong>확인 명령어:</strong><pre style="background:#f3f4f6;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{verification_command}</pre></div>' if verification_command else ''}
                    {f'<div style="margin-top:12px;"><strong>해결 방법:</strong><pre style="background:#f3f4f6;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{remediation}</pre></div>' if remediation else ''}
                </div>
"""
        html_content += """
            </div>
"""
    
    # ERROR 항목 상세 정보 추가
    error_items = [r for r in results.get("Results", []) if r.get("Result") == "ERROR"]
    if error_items:
        html_content += f"""
            <div style="margin-top:30px;">
                <h2 style="color:#374151;font-size:1.25rem;margin-bottom:20px;">⚠️ ERROR 항목 상세 정보 ({len(error_items)}건)</h2>
"""
        for result in error_items:
            check_id = result.get("CheckID", "UNKNOWN")
            check_name = check_info.get(check_id, {}).get("name", check_id)
            reason = result.get("Reason", "")
            remediation = result.get("Remediation", "")
            recommended_setting = result.get("RecommendedSetting", "")
            verification_command = result.get("VerificationCommand", "")
            description = result.get("Description", "")
            risk_level = result.get("RiskLevel", 0)
            
            html_content += f"""
                <div style="margin-bottom:24px;padding:20px;background:#f1f5f9;border-left:4px solid #64748b;border-radius:4px;">
                    <h3 style="color:#334155;font-size:1.1rem;margin-bottom:12px;">{check_id}: {check_name}</h3>
                    {f'<div style="margin-bottom:8px;"><strong>위험도:</strong> <span style="color:#475569;">{risk_level}/10</span></div>' if risk_level > 0 else ''}
                    {f'<div style="margin-bottom:8px;"><strong>설명:</strong> {description}</div>' if description else ''}
                    {f'<div style="margin-bottom:8px;"><strong>원인:</strong> <span style="color:#475569;">{reason}</span></div>' if reason else ''}
                    {f'<div style="margin-bottom:8px;"><strong>권장 설정:</strong><pre style="background:#e2e8f0;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{recommended_setting}</pre></div>' if recommended_setting else ''}
                    {f'<div style="margin-bottom:8px;"><strong>확인 명령어:</strong><pre style="background:#e2e8f0;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{verification_command}</pre></div>' if verification_command else ''}
                    {f'<div style="margin-top:12px;"><strong>해결 방법:</strong><pre style="background:#e2e8f0;padding:12px;border-radius:4px;margin-top:8px;white-space:pre-wrap;font-size:0.875rem;">{remediation}</pre></div>' if remediation else ''}
                </div>
"""
        html_content += """
            </div>
"""
    
    html_content += """
        </div>
        <div style="background:#f9fafb;padding:20px;text-align:center;color:#6b7280;font-size:0.875rem;">
            <p style="margin:0;">Generated by Kubernetes Security Scanner</p>
        </div>
    </div>
</body>
</html>
"""
    
    html = html_content
    
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
                    raise Exception(f"HTML 파일 형식이 올바르지 않습니다. 첫 줄: {first_line[:50]}")
    except Exception as e:
        print(f"[ERROR] HTML 파일 저장 실패: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
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
