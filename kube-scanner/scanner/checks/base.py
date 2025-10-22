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

    def get_info(self) -> Dict[str, str]:
        """체크 정보를 반환합니다."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description
        }
