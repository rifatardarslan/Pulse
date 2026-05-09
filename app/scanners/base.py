from abc import ABC, abstractmethod
from typing import Any, Dict, List
import uuid

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Interface Segregation: Yeni bir tarama aracı ekleyecek olan geliştirici,
#    sistemin iç yapısını (Docker API, Celery vs.) bilmek zorunda değildir.
#    Sadece bu 3 metodu doldurması sisteme entegre olması için yeterlidir.
# 2. Asynchronous execution: Docker I/O ve parsing işlemleri zaman aldığından 
#    metodlar asenkron tanımlanmıştır.
# 3. Read-Only Target: `target_dir` container'a read-only mount edilecek yoldur.

class BaseScanner(ABC):
    """
    Abstract Base Class for all vulnerability scanners in Pulse.
    Defines the strict contract for Docker-based scanning execution.
    """
    
    def __init__(self, scan_id: uuid.UUID, target_dir: str):
        self.scan_id = scan_id
        self.target_dir = target_dir

    @abstractmethod
    async def prepare_container(self) -> Dict[str, Any]:
        """
        Prepares Docker container arguments.
        
        Returns:
            Dict containing image name, read-only volume bindings, and environment variables.
            Example: {'image': 'zricethezav/gitleaks:latest', 'volumes': {...}}
        """
        pass

    @abstractmethod
    async def execute(self) -> tuple[int, str]:
        """
        Executes the scan within the isolated Docker container.
        
        Returns:
            tuple: (exit_code, raw_stdout_stderr)
        """
        pass

    @abstractmethod
    async def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Normalizes the tool-specific output (JSON/XML) into Pulse's standard format.
        
        Args:
            raw_output (str): The raw log or file output from the container.
            
        Returns:
            List[Dict]: Standardized vulnerability data ready for DB insertion.
        """
        pass
