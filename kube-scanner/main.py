from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from runner import run_all_checks, save_html
import uvicorn
import tempfile
import os

app = FastAPI(title="Cloud Scanner API")

# CORS (프론트엔드와 테스트할 때만 허용. 배포 시 더 엄격히 설정)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 모든 origin 허용 (개발용, 배포 시 제한 필요)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan")
def scan():
    """
    전체 체크를 실행하고 JSON 결과를 바로 반환합니다.
    (실제 환경에서는 비동기 job 큐 + 웹훅/폴링/웹소켓 방식 권장)
    """
    try:
        payload = run_all_checks()
        return payload
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/html", response_class=HTMLResponse)
def scan_html():
    """
    전체 체크를 실행하고 HTML 리포트를 반환합니다.
    """
    try:
        payload = run_all_checks()
        # 임시 파일에 HTML 저장
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
            temp_path = f.name
            save_html(payload, temp_path)
            # HTML 내용 읽기
            with open(temp_path, 'r', encoding='utf-8') as html_file:
                html_content = html_file.read()
            # 임시 파일 삭제
            os.unlink(temp_path)
            return HTMLResponse(content=html_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
def root():
    """
    웹 인터페이스 홈페이지
    """
    html = """
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kubernetes Security Scanner</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            
            .container {
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                padding: 60px;
                max-width: 600px;
                width: 100%;
                text-align: center;
            }
            
            h1 {
                font-size: 2.5rem;
                color: #1f2937;
                margin-bottom: 20px;
            }
            
            .subtitle {
                color: #6b7280;
                font-size: 1.125rem;
                margin-bottom: 40px;
            }
            
            .button {
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 16px 32px;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 1.125rem;
                margin: 10px;
                transition: transform 0.2s, box-shadow 0.2s;
                border: none;
                cursor: pointer;
            }
            
            .button:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
            }
            
            .button:active {
                transform: translateY(0);
            }
            
            .api-info {
                margin-top: 40px;
                padding-top: 40px;
                border-top: 1px solid #e5e7eb;
                text-align: left;
            }
            
            .api-info h2 {
                font-size: 1.25rem;
                color: #1f2937;
                margin-bottom: 16px;
            }
            
            .api-info code {
                background: #f3f4f6;
                padding: 2px 8px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                color: #ef4444;
            }
            
            .api-info ul {
                list-style: none;
                margin-top: 16px;
            }
            
            .api-info li {
                padding: 8px 0;
                color: #6b7280;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Kubernetes Security Scanner</h1>
            <p class="subtitle">Kubernetes 클러스터 보안 점검 도구</p>
            
            <button class="button" onclick="runScan()">스캔 실행하기</button>
            
            <div class="api-info">
                <h2>API 엔드포인트</h2>
                <ul>
                    <li><strong>POST</strong> <code>/scan</code> - JSON 결과 반환</li>
                    <li><strong>POST</strong> <code>/scan/html</code> - HTML 리포트 반환</li>
                </ul>
            </div>
        </div>
        
        <script>
            async function runScan() {
                const button = event.target;
                button.disabled = true;
                button.textContent = '스캔 중...';
                
                try {
                    const response = await fetch('/scan/html', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (response.ok) {
                        const html = await response.text();
                        const newWindow = window.open();
                        newWindow.document.write(html);
                        newWindow.document.close();
                    } else {
                        alert('스캔 실행 중 오류가 발생했습니다.');
                    }
                } catch (error) {
                    alert('스캔 실행 중 오류가 발생했습니다: ' + error.message);
                } finally {
                    button.disabled = false;
                    button.textContent = '스캔 실행하기';
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
