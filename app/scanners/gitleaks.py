import os
import json
import uuid
import tempfile
import asyncio
import shutil
from typing import Any, Dict, List

import docker
from docker.errors import DockerException, ContainerError

from app.scanners.base import BaseScanner
from app.models.vulnerability import Severity

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Asynchronous Execution (to_thread): Docker Python kütüphanesi senkron
#    bir kütüphanedir. Celery worker'ı ve event loop'u bloklamamak için 
#    container run işlemini `asyncio.to_thread` ile thread pool'a offload ettik.
# 2. Two-Volume Approach (Güvenlik): Kaynak kodun bulunduğu dizin (`target_dir`)
#    container'a 'ro' (Read-Only) olarak mount edilir. Kötü niyetli bir repo
#    içindeki kodların scanner ortamını manipüle etmesi engellenir.
#    Rapor üretimi için host üzerinde geçici bir `rw` (Read-Write) dizin yaratılır.
# 3. Memory & Storage Management (--rm): Docker konfigürasyonunda `auto_remove=True`
#    kullanılmıştır. Scanner işini bitirir bitirmez container imha edilir.
# 4. JSONB Mapping: Gitleaks'ten çıkan ham JSON verisi `raw_evidence` alanına
#    sıkıştırılmak üzere Pulse sistemine uygun bir Python dictionary listesine dönüştürülür.

class GitleaksScanner(BaseScanner):
    """
    Gitleaks Secret Scanner implementation for Pulse.
    """
    
    def __init__(self, scan_id: uuid.UUID, target_dir: str):
        super().__init__(scan_id, target_dir)
        self.client = docker.from_env()
        self.image = "zricethezav/gitleaks:latest"
        
        # Raporlama için host üzerinde izole ve geçici (temporary) bir dizin oluşturuyoruz.
        self.report_dir = tempfile.mkdtemp(prefix=f"pulse_report_{self.scan_id}_")
        self.report_file_host = os.path.join(self.report_dir, "report.json")
        self.report_file_container = "/report/report.json"

    async def prepare_container(self) -> Dict[str, Any]:
        """
        Prepares the Docker container execution arguments.
        """
        return {
            "image": self.image,
            "command": [
                "detect", 
                "--source", "/code", 
                "--report-path", self.report_file_container,
                "--report-format", "json",
                "--exit-code", "1"  # Zafiyet bulursa "Exit 1" döndürmesini zorlarız
            ],
            "volumes": {
                # Source Code (Host) -> /code (Container) : READ-ONLY
                self.target_dir: {"bind": "/code", "mode": "ro"},
                # Report Directory (Host) -> /report (Container) : READ-WRITE
                self.report_dir: {"bind": "/report", "mode": "rw"}
            },
            # Konteyner çıkışında kalıntı bırakmaz (Eşdeğeri: docker run --rm)
            "auto_remove": True,
            # Logları ve dönüş değerlerini okuyabilmek için
            "detach": False
        }

    async def execute(self) -> tuple[int, str]:
        """
        Executes Gitleaks within the container using Docker SDK.
        Returns (exit_code, output_content).
        """
        container_config = await self.prepare_container()
        
        def _run_container():
            try:
                # İmaj yoksa pull yap, varsa devam et (Image Layer Caching)
                try:
                    self.client.images.get(self.image)
                except docker.errors.ImageNotFound:
                    self.client.images.pull(self.image)

                # Container tetikleniyor...
                logs = self.client.containers.run(**container_config)
                
                # Exit 0: Tarama başarılı ve sıfır secret sızıntısı bulundu.
                return 0, logs.decode('utf-8')
                
            except ContainerError as e:
                # Gitleaks zafiyet bulduğunda (--exit-code 1) ContainerError fırlatır.
                # Bu Pulse için bir 'hata' değil, 'bulgu' sinyalidir.
                return e.exit_status, e.stderr.decode('utf-8') if e.stderr else str(e)
            except DockerException as e:
                return -1, f"Docker Engine Error: {str(e)}"
            except Exception as e:
                return -1, f"Unexpected Error: {str(e)}"

        # Asenkron bloklama: Docker thread üzerinde çalışsın
        exit_code, raw_logs = await asyncio.to_thread(_run_container)
        
        # Eğer tarama başarıyla çalıştıysa (Exit 0 -> Temiz, Exit 1 -> Zafiyet var)
        # Oluşturulan JSON raporunu Host'taki geçici dizinden okuyoruz.
        if exit_code in [0, 1]:
            if os.path.exists(self.report_file_host):
                try:
                    with open(self.report_file_host, 'r', encoding='utf-8') as f:
                        json_content = f.read()
                        if json_content.strip():
                            raw_logs = json_content
                except Exception as e:
                    raw_logs = f"Failed to read Gitleaks report file: {str(e)}\nContainer Logs: {raw_logs}"
                    exit_code = -1
                    
        # Temizlik: Güvenlik ve disk alanı için geçici Host dizini siliniyor
        shutil.rmtree(self.report_dir, ignore_errors=True)
            
        return exit_code, raw_logs

    async def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Maps Gitleaks JSON structure to Pulse Vulnerability Model architecture.
        """
        parsed_vulnerabilities = []
        
        try:
            results = json.loads(raw_output)
            
            if not isinstance(results, list):
                return parsed_vulnerabilities
                
            for finding in results:
                # Gitleaks çıktı haritasını (Mapping), Pulse DB modeline çevir.
                vuln = {
                    "tool_vulnerability_id": finding.get("RuleID", "unknown-rule"),
                    # Secret Leak'ler doğası gereği kurum için daima CRITICAL risk taşır.
                    "severity": Severity.CRITICAL,
                    "vulnerability_type": "secret-leak",
                    "file_path": finding.get("File", "unknown"),
                    "line_number": finding.get("StartLine", 0),
                    "description": finding.get("Description", "Exposed secret / credential found in repository"),
                    "raw_evidence": finding # JSONB için tam payload
                }
                parsed_vulnerabilities.append(vuln)
                
        except json.JSONDecodeError:
            # Container çökmesi veya parse edilemeyen error log dönmesi durumu
            # Bu durum Orchestration (Celery Worker) katmanında ele alınacak ve 'logs'a yazılacaktır.
            pass
            
        return parsed_vulnerabilities
