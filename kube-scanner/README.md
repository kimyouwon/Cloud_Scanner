# 🔒 Kubernetes Security Scanner

로컬 Kubernetes 클러스터의 보안 설정을 점검하는 데스크톱 애플리케이션입니다.

## ✨ 주요 기능

- **직관적인 GUI**: PySimpleGUI 기반의 사용하기 쉬운 인터페이스
- **자동 kubeconfig 감지**: 기본 kubeconfig 파일을 자동으로 찾아서 사용
- **실시간 스캔**: 진행 상황을 실시간으로 확인
- **결과 내보내기**: JSON/CSV 형식으로 스캔 결과 저장
- **심각도별 분류**: Critical, High, Medium, Low로 문제 분류
- **상세 정보 보기**: 각 문제에 대한 자세한 설명과 해결 방법 제공

## 🛡️ 검사 항목

### Pod 보안
- **CHK-001**: Pod hostNetwork 사용 검사
- **CHK-002**: Container privileged 모드 검사

### Control Plane 보안
- **CHK-API-001**: API Server 익명 접근 검사
- **CHK-API-002**: API Server 인증 설정 검사
- **CHK-API-003**: API Server TLS 설정 검사
- **CHK-API-004**: API Server 감사 로그 설정 검사
- **CHK-CTRL-001**: Controller 인증 제어 검사

## 🚀 설치 및 실행

### 🐧 Linux에서 실행

#### 방법 1: 자동 설치 스크립트 (권장)
```bash
# 설치 스크립트 실행
chmod +x install_linux.sh
./install_linux.sh

# 실행
./run_linux.sh gui    # GUI 모드
./run_linux.sh cli    # CLI 모드
./run_linux.sh api    # API 모드
```

#### 방법 2: Docker 사용
```bash
# Docker 이미지 빌드
docker build -t k8s-scanner .

# GUI 모드 (X11 포워딩 필요)
xhost +local:docker
docker run -it --rm -v ~/.kube:/root/.kube -e DISPLAY=$DISPLAY k8s-scanner

# API 모드
docker run -p 8000:8000 -v ~/.kube:/root/.kube k8s-scanner python3 main.py

# Docker Compose 사용
docker-compose --profile gui up    # GUI 모드
docker-compose --profile api up    # API 모드
```

#### 방법 3: 수동 설치
```bash
# Python 3.8+ 설치 (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk

# Python 3.8+ 설치 (CentOS/RHEL)
sudo yum install python3 python3-pip tkinter

# 의존성 설치
pip3 install -r requirements.txt

# 실행
python3 gui.py    # GUI 모드
python3 runner.py # CLI 모드
python3 main.py   # API 모드
```

### 🪟 Windows에서 실행

#### 방법 1: 실행 파일 사용 (권장)
1. `dist/K8sSecurityScanner.exe` 파일을 다운로드
2. 실행 파일을 더블클릭하여 실행
3. 또는 `install.bat`을 실행하여 시스템에 설치

#### 방법 2: 소스 코드에서 실행
1. Python 3.8+ 설치
2. 의존성 설치:
   ```bash
   pip install -r requirements.txt
   ```
3. GUI 실행:
   ```bash
   python gui.py
   ```

## 📋 사용 방법

1. **kubeconfig 설정**
   - 자동 감지된 kubeconfig 파일 사용 (기본)
   - 또는 "찾아보기" 버튼으로 직접 선택

2. **스캔 실행**
   - "🔍 스캔 시작" 버튼 클릭
   - 실시간으로 진행 상황 확인

3. **결과 확인**
   - "📋 상세 결과" 탭에서 발견된 문제들 확인
   - 각 항목을 클릭하여 상세 정보 보기
   - 심각도별로 분류된 요약 정보 확인

4. **결과 저장**
   - "📊 결과 내보내기" 버튼으로 JSON/CSV 파일로 저장

## 🔧 개발자용

### 빌드 방법
```bash
python build_exe.py
```

### 프로젝트 구조
```
kube-scanner/
├── gui.py                 # 메인 GUI 애플리케이션
├── runner.py              # 스캐너 실행 엔진
├── main.py                # FastAPI 웹 서버 (선택사항)
├── requirements.txt       # Python 의존성
├── build_exe.py          # 실행 파일 빌드 스크립트
└── scanner/
    └── checks/           # 보안 체크 모듈들
        ├── base.py       # 체크 기본 클래스
        ├── privileged_containers.py
        ├── host_network.py
        └── ... (기타 체크들)
```

### 새로운 체크 추가
1. `scanner/checks/` 디렉토리에 새 파일 생성
2. `base.py`의 `Check` 클래스를 상속
3. `id`, `name`, `category`, `severity` 속성 정의
4. `run()` 메서드 구현

## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 🤝 기여하기

버그 리포트나 기능 제안은 GitHub Issues를 통해 해주세요.

## ⚠️ 주의사항

- 이 도구는 로컬 Kubernetes 클러스터의 보안 설정을 점검합니다
- 프로덕션 환경에서 사용하기 전에 충분한 테스트를 수행하세요
- 발견된 문제들은 권장사항이며, 환경에 따라 다를 수 있습니다
