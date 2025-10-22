from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from runner import run_all_checks
import uvicorn

app = FastAPI(title="Cloud Scanner API")

# CORS (프론트엔드와 테스트할 때만 허용. 배포 시 더 엄격히 설정)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # 프론트 URL
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

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
