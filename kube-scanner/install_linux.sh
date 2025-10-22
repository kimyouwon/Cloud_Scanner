#!/bin/bash
# Kubernetes Security Scanner Linux 설치 스크립트

echo "🔒 Kubernetes Security Scanner Linux 설치 시작"
echo "================================================"

# Python 버전 확인
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python3가 설치되지 않았습니다. Python3를 먼저 설치하세요."
    exit 1
fi

# pip 업그레이드
echo "📦 pip 업그레이드 중..."
python3 -m pip install --upgrade pip

# 시스템 의존성 설치 (Ubuntu/Debian)
if command -v apt-get &> /dev/null; then
    echo "📦 시스템 의존성 설치 중..."
    sudo apt-get update
    sudo apt-get install -y python3-tk python3-dev build-essential
fi

# 시스템 의존성 설치 (CentOS/RHEL/Fedora)
if command -v yum &> /dev/null; then
    echo "📦 시스템 의존성 설치 중..."
    sudo yum install -y tkinter python3-devel gcc
elif command -v dnf &> /dev/null; then
    echo "📦 시스템 의존성 설치 중..."
    sudo dnf install -y tkinter python3-devel gcc
fi

# Python 의존성 설치
echo "📦 Python 패키지 설치 중..."
python3 -m pip install -r requirements.txt

# 실행 권한 부여
chmod +x run_linux.sh

echo "✅ 설치 완료!"
echo ""
echo "🚀 실행 방법:"
echo "1. GUI 모드: ./run_linux.sh gui"
echo "2. CLI 모드: ./run_linux.sh cli"
echo "3. API 모드: ./run_linux.sh api"
echo ""
echo "📝 사용법:"
echo "- kubeconfig 파일이 ~/.kube/config에 있으면 자동으로 감지됩니다"
echo "- 다른 위치의 kubeconfig를 사용하려면 GUI에서 직접 선택하세요"
