#!/bin/bash
# Kubernetes Security Scanner Linux 실행 스크립트

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 함수 정의
print_header() {
    echo -e "${BLUE}🔒 Kubernetes Security Scanner${NC}"
    echo "=================================="
}

check_dependencies() {
    echo -e "${YELLOW}📋 의존성 확인 중...${NC}"
    
    # Python 확인
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python3가 설치되지 않았습니다.${NC}"
        echo "Ubuntu/Debian: sudo apt-get install python3"
        echo "CentOS/RHEL: sudo yum install python3"
        echo "Fedora: sudo dnf install python3"
        exit 1
    fi
    
    # tkinter 확인
    python3 -c "import tkinter" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ tkinter가 설치되지 않았습니다.${NC}"
        echo "Ubuntu/Debian: sudo apt-get install python3-tk"
        echo "CentOS/RHEL: sudo yum install tkinter"
        echo "Fedora: sudo dnf install tkinter"
        exit 1
    fi
    
    # PySimpleGUI 확인
    python3 -c "import PySimpleGUI as sg; hasattr(sg, 'Window')" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}⚠️  PySimpleGUI가 설치되지 않았거나 버전이 올바르지 않습니다. 설치 중...${NC}"
        python3 -m pip uninstall PySimpleGUI -y 2>/dev/null
        python3 -m pip install --extra-index-url https://PySimpleGUI.net/install PySimpleGUI
    fi
    
    # kubernetes 확인
    python3 -c "import kubernetes" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}⚠️  kubernetes 라이브러리가 설치되지 않았습니다. 설치 중...${NC}"
        python3 -m pip install kubernetes
    fi
    
    echo -e "${GREEN}✅ 모든 의존성이 확인되었습니다.${NC}"
}

run_gui() {
    echo -e "${GREEN}🖥️  GUI 모드로 실행 중...${NC}"
    python3 gui.py
}

run_cli() {
    echo -e "${GREEN}💻 CLI 모드로 실행 중...${NC}"
    python3 runner.py
}

run_api() {
    echo -e "${GREEN}🌐 API 모드로 실행 중...${NC}"
    echo "API 서버가 http://localhost:8000에서 실행됩니다."
    echo "종료하려면 Ctrl+C를 누르세요."
    python3 main.py
}

show_help() {
    echo "사용법: $0 [모드]"
    echo ""
    echo "모드:"
    echo "  gui    - GUI 모드 (기본값)"
    echo "  cli    - CLI 모드"
    echo "  api    - API 모드"
    echo "  help   - 이 도움말 표시"
    echo ""
    echo "예시:"
    echo "  $0 gui    # GUI 모드로 실행"
    echo "  $0 cli    # CLI 모드로 실행"
    echo "  $0 api    # API 모드로 실행"
}

# 메인 로직
print_header

# 모드 확인
MODE=${1:-gui}

case $MODE in
    gui)
        check_dependencies
        run_gui
        ;;
    cli)
        check_dependencies
        run_cli
        ;;
    api)
        check_dependencies
        run_api
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}❌ 알 수 없는 모드: $MODE${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac




