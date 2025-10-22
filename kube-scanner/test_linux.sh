#!/bin/bash
# Linux 환경에서 스캐너 테스트 스크립트

echo "🧪 Kubernetes Security Scanner Linux 테스트"
echo "============================================="

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 테스트 함수
test_python() {
    echo -e "${YELLOW}📋 Python 환경 테스트...${NC}"
    python3 --version
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Python3 정상${NC}"
    else
        echo -e "${RED}❌ Python3 오류${NC}"
        return 1
    fi
}

test_tkinter() {
    echo -e "${YELLOW}📋 tkinter 테스트...${NC}"
    python3 -c "import tkinter; print('tkinter 정상')" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ tkinter 정상${NC}"
    else
        echo -e "${RED}❌ tkinter 오류 - GUI 모드 사용 불가${NC}"
        return 1
    fi
}

test_pysimplegui() {
    echo -e "${YELLOW}📋 PySimpleGUI 테스트...${NC}"
    python3 -c "import PySimpleGUI; print('PySimpleGUI 정상')" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ PySimpleGUI 정상${NC}"
    else
        echo -e "${RED}❌ PySimpleGUI 오류${NC}"
        return 1
    fi
}

test_kubernetes() {
    echo -e "${YELLOW}📋 Kubernetes 라이브러리 테스트...${NC}"
    python3 -c "import kubernetes; print('kubernetes 라이브러리 정상')" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ kubernetes 라이브러리 정상${NC}"
    else
        echo -e "${RED}❌ kubernetes 라이브러리 오류${NC}"
        return 1
    fi
}

test_kubeconfig() {
    echo -e "${YELLOW}📋 kubeconfig 파일 테스트...${NC}"
    if [ -f ~/.kube/config ]; then
        echo -e "${GREEN}✅ kubeconfig 파일 발견: ~/.kube/config${NC}"
        return 0
    elif [ -f ./kubeconfig ]; then
        echo -e "${GREEN}✅ kubeconfig 파일 발견: ./kubeconfig${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  kubeconfig 파일을 찾을 수 없습니다${NC}"
        echo "   GUI에서 직접 선택하거나 ~/.kube/config에 파일을 배치하세요"
        return 0
    fi
}

test_scanner_import() {
    echo -e "${YELLOW}📋 스캐너 모듈 테스트...${NC}"
    python3 -c "
import sys
sys.path.append('.')
try:
    from scanner.checks.base import Check
    print('✅ base.py 모듈 정상')
except Exception as e:
    print(f'❌ base.py 모듈 오류: {e}')
    sys.exit(1)

try:
    from scanner.checks.privileged_containers import PrivilegedCheck
    print('✅ privileged_containers 모듈 정상')
except Exception as e:
    print(f'❌ privileged_containers 모듈 오류: {e}')
    sys.exit(1)
"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ 스캐너 모듈 정상${NC}"
    else
        echo -e "${RED}❌ 스캐너 모듈 오류${NC}"
        return 1
    fi
}

# 모든 테스트 실행
echo "테스트 시작..."
echo ""

test_python || exit 1
test_tkinter || echo "GUI 모드 사용 불가 (CLI/API 모드는 가능)"
test_pysimplegui || exit 1
test_kubernetes || exit 1
test_kubeconfig
test_scanner_import || exit 1

echo ""
echo -e "${GREEN}🎉 모든 테스트 통과!${NC}"
echo ""
echo "사용 가능한 모드:"
echo "  ./run_linux.sh gui  - GUI 모드 (tkinter 필요)"
echo "  ./run_linux.sh cli  - CLI 모드"
echo "  ./run_linux.sh api  - API 모드"
echo ""
echo "테스트 완료!"
