# 🐧 Linux 설치 가이드

## 빠른 설치 (권장)

```bash
# 1. 파일 다운로드 후 압축 해제
# 2. 설치 스크립트 실행
chmod +x install_linux.sh
./install_linux.sh

# 3. 실행
./run_linux.sh gui
```

## 수동 설치

### Ubuntu/Debian
```bash
# 시스템 패키지 설치
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk python3-dev build-essential

# Python 패키지 설치
pip3 install PySimpleGUI==5.0.8.3
pip3 install kubernetes
pip3 install fastapi uvicorn

# 실행
python3 gui.py
```

### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install python3 python3-pip tkinter python3-devel gcc

# Fedora
sudo dnf install python3 python3-pip tkinter python3-devel gcc

# Python 패키지 설치
pip3 install PySimpleGUI==5.0.8.3
pip3 install kubernetes
pip3 install fastapi uvicorn

# 실행
python3 gui.py
```

## 문제 해결

### PySimpleGUI 버전 오류
```bash
# 기존 버전 제거
pip3 uninstall PySimpleGUI

# 호환 버전 설치
pip3 install PySimpleGUI==5.0.8.3
```

### tkinter 오류 (GUI 모드)
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# CentOS/RHEL
sudo yum install tkinter

# Fedora
sudo dnf install tkinter
```

### 권한 오류
```bash
# 실행 권한 부여
chmod +x *.sh

# 또는 직접 실행
python3 gui.py
```

## 실행 모드

- **GUI 모드**: `./run_linux.sh gui` 또는 `python3 gui.py`
- **CLI 모드**: `./run_linux.sh cli` 또는 `python3 runner.py`
- **API 모드**: `./run_linux.sh api` 또는 `python3 main.py`

## Docker 사용

```bash
# Docker 이미지 빌드
docker build -t k8s-scanner .

# GUI 모드 (X11 포워딩)
xhost +local:docker
docker run -it --rm -v ~/.kube:/root/.kube -e DISPLAY=$DISPLAY k8s-scanner

# API 모드
docker run -p 8000:8000 -v ~/.kube:/root/.kube k8s-scanner python3 main.py
```










