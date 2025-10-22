#!/usr/bin/env python3
"""
Kubernetes Security Scanner 실행 파일 빌드 스크립트
PyInstaller를 사용하여 단일 실행 파일을 생성합니다.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def install_pyinstaller():
    """PyInstaller를 설치합니다."""
    print("PyInstaller 설치 중...")
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    print("PyInstaller 설치 완료")

def build_executable():
    """실행 파일을 빌드합니다."""
    print("실행 파일 빌드 시작...")
    
    # PyInstaller 명령어 구성
    cmd = [
        "pyinstaller",
        "--onefile",                    # 단일 실행 파일로 생성
        "--windowed",                   # 콘솔 창 숨김 (GUI 앱)
        "--name=K8sSecurityScanner",    # 실행 파일 이름
        "--icon=icon.ico",              # 아이콘 (있는 경우)
        "--add-data=scanner;scanner",   # scanner 디렉토리 포함
        "--hidden-import=kubernetes",   # kubernetes 모듈 명시적 포함
        "--hidden-import=PySimpleGUI",  # PySimpleGUI 모듈 명시적 포함
        "--hidden-import=fastapi",      # fastapi 모듈 명시적 포함
        "--hidden-import=uvicorn",      # uvicorn 모듈 명시적 포함
        "gui.py"                        # 메인 파일
    ]
    
    # 아이콘이 없으면 해당 옵션 제거
    if not os.path.exists("icon.ico"):
        cmd = [arg for arg in cmd if not arg.startswith("--icon")]
    
    try:
        subprocess.run(cmd, check=True)
        print("빌드 완료!")
        print(f"실행 파일 위치: {os.path.join('dist', 'K8sSecurityScanner.exe')}")
    except subprocess.CalledProcessError as e:
        print(f"빌드 실패: {e}")
        return False
    
    return True

def create_installer_script():
    """간단한 설치 스크립트를 생성합니다."""
    installer_content = '''@echo off
echo Kubernetes Security Scanner 설치 중...
echo.

REM 실행 파일을 Program Files에 복사
if not exist "C:\\Program Files\\K8sSecurityScanner" (
    mkdir "C:\\Program Files\\K8sSecurityScanner"
)

copy "K8sSecurityScanner.exe" "C:\\Program Files\\K8sSecurityScanner\\"
echo 실행 파일이 설치되었습니다.

REM 바탕화면에 바로가기 생성
echo [InternetShortcut] > "%USERPROFILE%\\Desktop\\K8s Security Scanner.url"
echo URL=file:///C:/Program Files/K8sSecurityScanner/K8sSecurityScanner.exe >> "%USERPROFILE%\\Desktop\\K8s Security Scanner.url"
echo IconFile=C:\\Program Files\\K8sSecurityScanner\\K8sSecurityScanner.exe >> "%USERPROFILE%\\Desktop\\K8s Security Scanner.url"
echo IconIndex=0 >> "%USERPROFILE%\\Desktop\\K8s Security Scanner.url"

echo 바탕화면에 바로가기가 생성되었습니다.
echo.
echo 설치가 완료되었습니다!
pause
'''
    
    with open("install.bat", "w", encoding="utf-8") as f:
        f.write(installer_content)
    
    print("install.bat 파일이 생성되었습니다.")

def main():
    print("🔒 Kubernetes Security Scanner 빌드 도구")
    print("=" * 50)
    
    # 현재 디렉토리 확인
    if not os.path.exists("gui.py"):
        print("오류: gui.py 파일을 찾을 수 없습니다.")
        print("이 스크립트를 프로젝트 루트 디렉토리에서 실행하세요.")
        return
    
    # PyInstaller 설치 확인 및 설치
    try:
        import PyInstaller
        print("PyInstaller가 이미 설치되어 있습니다.")
    except ImportError:
        install_pyinstaller()
    
    # 빌드 실행
    if build_executable():
        print("\n빌드 성공!")
        create_installer_script()
        
        print("\n📁 생성된 파일들:")
        print("- dist/K8sSecurityScanner.exe (실행 파일)")
        print("- install.bat (설치 스크립트)")
        
        print("\n🚀 사용 방법:")
        print("1. dist/K8sSecurityScanner.exe를 실행하거나")
        print("2. install.bat을 실행하여 시스템에 설치")
        
    else:
        print("빌드 실패!")

if __name__ == "__main__":
    main()
