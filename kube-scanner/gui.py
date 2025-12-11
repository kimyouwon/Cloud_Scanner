# gui.py
import PySimpleGUI as sg
import subprocess
import threading
import json
import sys
import os
from queue import Queue, Empty

# runner.py 경로 (프로젝트 구조에 맞게 수정)
SCANNER_PATH = os.path.join(os.path.dirname(__file__), "runner.py")

def enqueue_output(pipe, queue):
    """비동기적으로 stdout 라인들을 큐에 넣음"""
    for line in iter(pipe.readline, b''):
        if not line:
            break
        queue.put(line.decode(errors='ignore'))
    pipe.close()

def run_scanner(kubeconfig_path, window):
    """서브프로세스로 scanner_runner.py 실행하고 JSON-lines 파싱하여 윈도우에 이벤트 보냄"""
    cmd = [sys.executable, SCANNER_PATH]
    if kubeconfig_path:
        cmd += ["--kubeconfig", kubeconfig_path]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as e:
        window.write_event_value('-ERROR-', f"실행 실패: {e}")
        return

    q = Queue()
    t = threading.Thread(target=enqueue_output, args=(proc.stdout, q))
    t.daemon = True
    t.start()

    # stderr 읽는 쓰레드 (선택)
    def read_err(pipe):
        for l in iter(pipe.readline, b''):
            if not l: break
            window.write_event_value('-LOG-', {'type':'stderr','msg': l.decode(errors='ignore')})
        pipe.close()
    threading.Thread(target=read_err, args=(proc.stderr,), daemon=True).start()

    # 프로세스가 종료될 때까지 큐를 폴링하여 창에 보냄
    while True:
        try:
            line = q.get(timeout=0.1)
        except Empty:
            if proc.poll() is not None:
                break
            continue

        txt = line.strip()
        # JSON이면 파싱해서 event로 전달, 아니면 일반 로그
        try:
            obj = json.loads(txt)
            # 이벤트 타입을 기준으로 처리
            if isinstance(obj, dict) and obj.get('type') in ('finding','result','log','exit'):
                window.write_event_value('-SCAN-EVENT-', obj)
            else:
                # 일반 페이로드(기본 result 형태 등)
                window.write_event_value('-SCAN-EVENT-', {'type':'payload','payload': obj})
        except Exception:
            window.write_event_value('-LOG-', {'type':'stdout','msg': txt})

    # 프로세스 종료 후 남은 이벤트 전송
    code = proc.poll()
    window.write_event_value('-LOG-', {'type':'info', 'msg': f"Scanner 프로세스 종료 코드: {code}"})
    window.write_event_value('-DONE-', code)

def build_layout():
    layout = [
        # 헤더
        [sg.Text("🔒 Kubernetes Security Scanner", font=("Helvetica", 20, "bold"), justification='center', expand_x=True)],
        [sg.Text("로컬 Kubernetes 클러스터의 보안 설정을 점검합니다", font=("Helvetica", 10), justification='center', expand_x=True)],
        [sg.HSeparator()],
        
        # 설정 섹션
        [sg.Frame("설정", [
            [sg.Text("kubeconfig 파일:", size=(15, 1)), 
             sg.Input(key='-KUBE-', size=(50,1), placeholder_text="비워두면 기본 ~/.kube/config 사용"), 
             sg.FileBrowse("찾아보기", file_types=(("Kubeconfig 파일", "*.yaml *.yml"), ("모든 파일", "*.*")))],
            [sg.Text("자동 감지된 kubeconfig:", size=(15, 1)), sg.Text("", key='-AUTO-KUBE-', text_color='blue')]
        ], expand_x=True)],
        
        [sg.HSeparator()],
        
        # 제어 버튼
        [sg.Button("🔍 스캔 시작", key='-START-', size=(15, 2), button_color=('white', 'green')), 
         sg.Button("⏹️ 중지", key='-STOP-', size=(15, 2), button_color=('white', 'red'), disabled=True),
         sg.Button("📊 결과 내보내기", key='-EXPORT-', size=(15, 2), disabled=True),
         sg.Button("❌ 종료", key='-EXIT-', size=(15, 2))],
        
        [sg.HSeparator()],
        
        # 진행 상태
        [sg.Frame("진행 상태", [
            [sg.ProgressBar(100, orientation='h', size=(50, 20), key='-PROGRESS-')],
            [sg.Text("준비됨", key='-STATUS-', size=(50, 1))]
        ], expand_x=True)],
        
        [sg.HSeparator()],
        
        # 결과 요약
        [sg.Frame("스캔 결과 요약", [
            [sg.Text("총 발견된 문제:", size=(15, 1)), sg.Text("0", key='-TOTAL-', font=("Helvetica", 12, "bold"))],
            [sg.Text("Critical:", size=(15, 1)), sg.Text("0", key='-CRITICAL-', text_color='red', font=("Helvetica", 10, "bold"))],
            [sg.Text("High:", size=(15, 1)), sg.Text("0", key='-HIGH-', text_color='orange', font=("Helvetica", 10, "bold"))],
            [sg.Text("Medium:", size=(15, 1)), sg.Text("0", key='-MEDIUM-', text_color='yellow', font=("Helvetica", 10, "bold"))],
            [sg.Text("Low:", size=(15, 1)), sg.Text("0", key='-LOW-', text_color='blue', font=("Helvetica", 10, "bold"))]
        ], expand_x=True)],
        
        [sg.HSeparator()],
        
        # 탭 레이아웃
        [sg.TabGroup([[
            sg.Tab("📋 상세 결과", [
                [sg.Table(values=[], 
                         headings=["체크ID", "결과", "심각도", "객체타입", "객체명", "네임스페이스", "이유"], 
                         key='-TABLE-', 
                         auto_size_columns=False, 
                         col_widths=[12, 8, 10, 12, 20, 15, 40], 
                         justification='left', 
                         num_rows=12,
                         enable_events=True,
                         select_mode=sg.TABLE_SELECT_MODE_BROWSE)],
                [sg.Text("선택된 항목의 상세 정보:", font=("Helvetica", 10, "bold"))],
                [sg.Multiline(size=(None, 4), key='-DETAIL-', disabled=True, autoscroll=True)]
            ]),
            sg.Tab("📝 실시간 로그", [
                [sg.Multiline(size=(None, 20), key='-LOG-', autoscroll=True, disabled=True, font=("Consolas", 9))]
            ])
        ]], expand_x=True, expand_y=True)]
    ]
    return layout

def detect_kubeconfig():
    """자동으로 kubeconfig 파일을 감지합니다."""
    import os
    home = os.path.expanduser("~")
    default_paths = [
        os.path.join(home, ".kube", "config"),
        os.path.join(os.getcwd(), "kubeconfig"),
        os.path.join(os.getcwd(), "config")
    ]
    
    for path in default_paths:
        if os.path.exists(path):
            return path
    return ""

def update_severity_counts(findings, window):
    """심각도별 카운트를 업데이트합니다."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    for finding in findings:
        severity = finding.get('Severity', 'Low')
        if severity in counts:
            counts[severity] += 1
    
    window['-TOTAL-'].update(str(len(findings)))
    window['-CRITICAL-'].update(str(counts["Critical"]))
    window['-HIGH-'].update(str(counts["High"]))
    window['-MEDIUM-'].update(str(counts["Medium"]))
    window['-LOW-'].update(str(counts["Low"]))

def main():
    # PySimpleGUI 버전에 따라 테마 설정
    try:
        sg.theme('DarkBlue3')
    except AttributeError:
        # 구버전에서는 테마 설정이 없을 수 있음
        pass
    
    window = sg.Window("🔒 Kubernetes Security Scanner", build_layout(), finalize=True, resizable=True)

    scan_thread = None
    findings = []
    scan_running = False

    # 자동 kubeconfig 감지
    auto_kube = detect_kubeconfig()
    if auto_kube:
        window['-AUTO-KUBE-'].update(auto_kube)
        window['-KUBE-'].update(auto_kube)

    while True:
        event, values = window.read(timeout=200)
        
        if event in (sg.WIN_CLOSED, '-EXIT-'):
            if scan_running:
                if sg.popup_yes_no("스캔이 진행 중입니다. 정말 종료하시겠습니까?") == "Yes":
                    break
            else:
                break

        if event == '-START-':
            if scan_running:
                sg.popup("이미 스캔이 진행 중입니다.")
                continue
                
            kube = values['-KUBE-'].strip() or ''
            if not kube and not auto_kube:
                sg.popup("kubeconfig 파일을 선택하거나 자동 감지된 파일을 사용하세요.")
                continue
                
            # UI 초기화
            findings = []
            window['-TABLE-'].update(values=[])
            window['-DETAIL-'].update("")
            window['-LOG-'].update("")
            window['-PROGRESS-'].update(0)
            window['-STATUS-'].update("스캔 시작 중...")
            window['-START-'].update(disabled=True)
            window['-STOP-'].update(disabled=False)
            window['-EXPORT-'].update(disabled=True)
            scan_running = True
            
            # 심각도 카운트 초기화
            update_severity_counts([], window)
            
            # 백그라운드로 실행
            scan_thread = threading.Thread(target=run_scanner, args=(kube, window), daemon=True)
            scan_thread.start()

        if event == '-STOP-':
            if scan_thread and scan_thread.is_alive():
                # 프로세스 종료는 복잡하므로 경고만 표시
                sg.popup("스캔 중지 요청됨. 현재 체크가 완료되면 중지됩니다.")
            scan_running = False
            window['-START-'].update(disabled=False)
            window['-STOP-'].update(disabled=True)
            window['-STATUS-'].update("중지됨")

        if event == '-EXPORT-':
            if not findings:
                sg.popup("내보낼 결과가 없습니다.")
                continue
                
            filename = sg.popup_get_file("결과를 저장할 파일을 선택하세요", 
                                       save_as=True, 
                                       file_types=(("JSON 파일", "*.json"), ("CSV 파일", "*.csv")))
            if filename:
                try:
                    if filename.endswith('.json'):
                        with open(filename, 'w', encoding='utf-8') as f:
                            json.dump(findings, f, ensure_ascii=False, indent=2)
                    elif filename.endswith('.csv'):
                        import csv
                        with open(filename, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.writer(f)
                            writer.writerow(["체크ID", "결과", "심각도", "객체타입", "객체명", "네임스페이스", "이유"])
                            for finding in findings:
                                writer.writerow(finding)
                    sg.popup(f"결과가 {filename}에 저장되었습니다.")
                except Exception as e:
                    sg.popup(f"파일 저장 실패: {str(e)}")

        if event == '-TABLE-':
            # 테이블 선택 이벤트
            if values['-TABLE-']:
                selected_row = values['-TABLE-'][0]
                if selected_row < len(findings):
                    finding = findings[selected_row]
                    detail = f"체크 ID: {finding[0]}\n"
                    detail += f"결과: {finding[1]}\n"
                    detail += f"심각도: {finding[2]}\n"
                    detail += f"객체 타입: {finding[3]}\n"
                    detail += f"객체명: {finding[4]}\n"
                    detail += f"네임스페이스: {finding[5]}\n"
                    detail += f"이유: {finding[6]}"
                    window['-DETAIL-'].update(detail)

        if event == '-SCAN-EVENT-':
            obj = values[event]
            t = obj.get('type')
            if t == 'finding':
                payload = obj.get('payload') or {}
                # 심각도 정보 추가
                severity = payload.get('Severity', 'Low')
                row = [
                    payload.get('CheckID') or payload.get('check') or '—',
                    payload.get('Result') or payload.get('result') or '—',
                    severity,
                    payload.get('ObjectType') or payload.get('objectType') or '—',
                    payload.get('ObjectName') or payload.get('objectName') or '—',
                    payload.get('Namespace') or payload.get('namespace') or '—',
                    payload.get('Reason') or payload.get('reason') or json.dumps(payload.get('Evidence', {}))[:100]
                ]
                findings.append(row)
                window['-TABLE-'].update(values=findings)
                update_severity_counts(findings, window)
                
            elif t == 'result':
                payload = obj.get('payload')
                window['-LOG-'].print("최종 결과(요약): " + json.dumps(payload, ensure_ascii=False))
            elif t == 'log' or t == 'payload':
                window['-LOG-'].print(json.dumps(obj, ensure_ascii=False))
            elif t == 'exit':
                window['-LOG-'].print("스캐너가 exit 이벤트 보냄")

        if event == '-ERROR-':
            window['-LOG-'].print("ERROR: " + str(values[event]))
            window['-STATUS-'].update("오류 발생")

        if event == '-DONE-':
            window['-LOG-'].print("스캔 완료")
            window['-STATUS-'].update("완료")
            window['-PROGRESS-'].update(100)
            window['-START-'].update(disabled=False)
            window['-STOP-'].update(disabled=True)
            window['-EXPORT-'].update(disabled=False)
            scan_running = False

    window.close()

if __name__ == "__main__":
    main()
