# Kubernetes Security Scanner Docker 이미지
FROM python:3.11-slim

# 메타데이터
LABEL maintainer="K8s Security Scanner"
LABEL description="Kubernetes 보안 설정 스캐너"
LABEL version="1.0.0"

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    tk \
    python3-tk \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# Python 의존성 파일 복사
COPY requirements.txt .

# Python 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 파일 복사
COPY . .

# 실행 권한 부여
RUN chmod +x run_linux.sh

# 포트 노출 (API 모드용)
EXPOSE 8000

# 기본 명령어 (GUI 모드)
CMD ["python3", "gui.py"]

# 사용법:
# GUI 모드: docker run -it --rm -v ~/.kube:/root/.kube k8s-scanner
# CLI 모드: docker run -it --rm -v ~/.kube:/root/.kube k8s-scanner python3 runner.py
# API 모드: docker run -p 8000:8000 -v ~/.kube:/root/.kube k8s-scanner python3 main.py
