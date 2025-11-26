# base.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class Check(ABC):
    """
    모든 보안 체크의 기본 클래스
    """
    id: str = ""
    name: str = ""
    category: str = ""
    severity: str = ""
    description: str = ""
    points: int = 0  # 이 체크 항목의 점수 (PASS 시 획득, FAIL/ERROR 시 0점)
    risk_level: int = 0  # 위험도 (1-10)
    recommended_setting: str = ""  # 권장 설정
    verification_command: str = ""  # 실제 확인 명령어

    @abstractmethod
    def run(self, k8s_client=None, kubeconfig: str = '') -> List[Dict[str, Any]]:
        """
        보안 체크를 실행하고 결과를 반환합니다.
        
        Args:
            k8s_client: Kubernetes 클라이언트 객체 (Pod/Container 체크용)
            kubeconfig: kubeconfig 파일 경로 (Control Plane 체크용)
            
        Returns:
            List[Dict]: 체크 결과 리스트
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """체크 정보를 반환합니다."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "points": self.points,
            "risk_level": self.risk_level,
            "recommended_setting": self.recommended_setting,
            "verification_command": self.verification_command
        }

