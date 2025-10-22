# gui.py
import PySimpleGUI as sg
import subprocess
import threading
import json
import sys
import os
from queue import Queue, Empty

# scanner_runner.py 경로 (프로젝트 구조에 맞게 수정)
SCANNER_PATH = os.path.join(os.path.dirname(__file__), "scanner", "scanner_runner.py")

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
        [sg.Text("Kubernetes Security Scanner", font=("Helvetica", 16))],
        [sg.Text("kubeconfig 경로 (비워두면 기본 ~/.kube/config 사용):"), sg.Input(key='-KUBE-', size=(60,1)), sg.FileBrowse(file_types=(("Kubeconfig","*"),))],
        [sg.Button("Start Scan", key='-START-'), sg.Button("Exit")],
        [sg.Text("실시간 로그:", font=("Helvetica", 12))],
        [sg.Multiline(size=(100, 15), key='-LOG-', autoscroll=True, disabled=True)],
        [sg.Text("Findings:"), sg.Text("", key='-COUNT-')],
        [sg.Table(values=[], headings=["CheckID","Result","ObjectType","ObjectName","Namespace","Reason"], key='-TABLE-', auto_size_columns=False, col_widths=[10,8,12,20,12,30], justification='left', num_rows=8)]
    ]
    return layout

def main():
    sg.theme('DarkBlue3')
    window = sg.Window("k8s-scanner GUI", build_layout(), finalize=True)

    scan_thread = None

    findings = []

    while True:
        event, values = window.read(timeout=200)
        if event in (sg.WIN_CLOSED, 'Exit'):
            break

        if event == '-START-':
            # 중복 실행 방지
            if scan_thread and scan_thread.is_alive():
                sg.popup("이미 스캔 중입니다.")
                continue
            kube = values['-KUBE-'].strip() or ''
            window['-LOG-'].update("스캔 시작...\n")
            findings = []
            window['-TABLE-'].update(values=[])
            # 백그라운드로 실행
            scan_thread = threading.Thread(target=run_scanner, args=(kube, window), daemon=True)
            scan_thread.start()

        if event == '-LOG-':
            # 내부로 쓰는 이벤트 없음(보류)
            pass

        if event == '-SCAN-EVENT-':
            obj = values[event]
            t = obj.get('type')
            if t == 'finding':
                payload = obj.get('payload') or {}
                # 적절히 테이블용 행 만들기
                row = [
                    payload.get('CheckID') or payload.get('check') or '—',
                    payload.get('Result') or payload.get('result') or '—',
                    payload.get('ObjectType') or payload.get('objectType') or '—',
                    payload.get('ObjectName') or payload.get('objectName') or '—',
                    payload.get('Namespace') or payload.get('namespace') or '—',
                    payload.get('Reason') or payload.get('reason') or json.dumps(payload.get('Evidence', {}))[:100]
                ]
                findings.append(row)
                window['-TABLE-'].update(values=findings)
                window['-COUNT-'].update(f"총 {len(findings)}개 발견")
            elif t == 'result':
                payload = obj.get('payload')
                window['-LOG-'].print("최종 결과(요약): " + json.dumps(payload))
            elif t == 'log' or t == 'payload':
                window['-LOG-'].print(json.dumps(obj))
            elif t == 'exit':
                window['-LOG-'].print("스캐너가 exit 이벤트 보냄")
            else:
                # 기타 dict 형태
                window['-LOG-'].print(json.dumps(obj))

        if event == '-LOG-':
            pass

        if event == '-ERROR-':
            window['-LOG-'].print("ERROR: " + str(values[event]))

        if event == '-DONE-':
            window['-LOG-'].print("스캔 스레드 종료 코드: " + str(values[event]))

        # 일반 로그 이벤트 (문자열)
        if event == '-LOG-STRING-':  # not used but kept if needed
            window['-LOG-'].print(values[event])

    window.close()

if __name__ == "__main__":
    main()
