import os
import uuid
import tempfile
import asyncio
import shutil
import traceback
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from app.tasks.worker import celery_app
from app.core import database
from app.models.project import Project
from app.models.scan import Scan, ScanStatus, ScannerType
from app.models.vulnerability import Vulnerability, Severity

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Async-in-Sync (asyncio.run): Celery varsayılan olarak senkron bir Python process'idir.
#    Fakat Pulse'un kalbi (DB ve Scanner API'leri) asenkron çalışır. Celery task'ı
#    çalıştığında, izole bir event loop açarak iş mantığımızı (`async_scan_logic`)
#    non-blocking şekilde yönetmesini sağlıyoruz.
# 2. Atomicity & State Management: Task başlar başlamaz `Scan` tablosunda `RUNNING` 
#    statüsünde bir kimlik oluşturur. Klonda veya taramada en ufak bir Exception fırlarsa, 
#    global try-except bloğu bunu yakalar, DB transaction'ını `rollback` eder ve 
#    `Scan` kaydını `FAILED` yapıp Stack Trace'i basar.
# 3. Zero-Storage-Leak (finally): Tarama sonucu ne olursa olsun (başarılı veya crash),
#    `finally` bloğu host üzerindeki kaynak kod klonunu (target_dir) kalıcı olarak siler.
# 4. acks_late=True: Bu Celery parametresi kritik. Eğer tarama devam ederken sunucunun 
#    fişi çekilirse (Worker Crash), task henüz ACK almadığı için Redis kuyruğunda kalır ve
#    sunucu tekrar açıldığında baştan koşturulur (Fail-safe architecture).

async def run_ai_analysis_task(vulnerability_id: str, vuln_data: dict):
    """
    Background AI Analysis Task
    """
    from app.services.ai_service import generate_remediation
    from app.models.remediation import Remediation
    
    async with database.AsyncSessionLocal() as session:
        try:
            ai_res = await generate_remediation(vuln_data)
            if ai_res.get("status") == "success":
                rem = Remediation(
                    vulnerability_id=uuid.UUID(vulnerability_id),
                    ai_model=ai_res["model_used"],
                    suggested_fix=ai_res["suggested_fix"],
                    remediation_steps=ai_res["remediation_steps"],
                    confidence_score=ai_res["confidence_score"],
                    is_reviewed=False
                )
                session.add(rem)
                await session.commit()
                logger.info(f"AI Remediation saved for vuln {vulnerability_id}")
        except Exception as e:
            logger.error(f"AI Task Failed for vuln {vulnerability_id}: {str(e)}")

@celery_app.task(name="orchestration.process_ai_enrichment", rate_limit="30/m")
def process_ai_enrichment(vulnerability_id: str, vuln_data: dict):
    """Celery wrapper for AI analysis"""
    asyncio.run(run_ai_analysis_task(vulnerability_id, vuln_data))

@celery_app.task(name="orchestration.trigger_enrichment_batch")
def trigger_enrichment_batch(vuln_list: list):
    """Batch trigger for AI enrichment tasks to keep the main scan loop ultra-fast"""
    for v_id, v_data in vuln_list:
        process_ai_enrichment.delay(v_id, v_data)

async def run_pip_audit(target_dir: str) -> list:
    """Runs pip-audit and returns findings"""
    import json
    
    requirements_path = os.path.join(target_dir, "requirements.txt")
    if not os.path.exists(requirements_path):
        return []
        
    audit_cmd = ["pip-audit", "-r", "requirements.txt", "-f", "json"]
    process = await asyncio.create_subprocess_exec(
        *audit_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=target_dir
    )
    stdout, stderr = await process.communicate()
    
    findings = []
    if stdout:
        try:
            data = json.loads(stdout.decode('utf-8'))
            # pip-audit returns a list of dependencies, each with a list of vulnerabilities
            for dep in data.get("dependencies", []):
                dep_name = dep.get("name")
                version = dep.get("version")
                for vuln in dep.get("vulns", []):
                    findings.append({
                        "id": vuln.get("id"),
                        "package": dep_name,
                        "version": version,
                        "fix_versions": vuln.get("fix_versions", []),
                        "description": vuln.get("description", "Dependency vulnerability")
                    })
        except Exception as e:
            logger.error(f"Failed to parse pip-audit output: {e}")
            
    return findings

async def async_scan_logic(project_id: str, scan_id_str: str, skip_ai: bool = False) -> dict:
    """Asenkron Orchestration Mantığı"""
    project_uuid = uuid.UUID(project_id)
    scan_uuid = uuid.UUID(scan_id_str)
    
    workspace_base = "/tmp/pulse_workspaces"
    os.makedirs(workspace_base, exist_ok=True)
    target_dir = tempfile.mkdtemp(prefix=f"scan_{scan_id_str}_", dir=workspace_base)
    
    async with database.AsyncSessionLocal() as session:
        try:
            # Projeyi ve Scan kaydını kontrol et
            project = await session.get(Project, project_uuid)
            scan = await session.get(Scan, scan_uuid)
            
            if not project or not scan:
                shutil.rmtree(target_dir, ignore_errors=True)
                return {"status": "error", "message": "Project or Scan record not found in DB."}
                
            # 2. Durumu RUNNING yap
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(scan)
            
            # 3. Repo Klonlama Süreci
            # --depth 1: Sadece son commit'i al — tarihçeyi indirme.
            # Güvenlik taramaları için git geçmişi gerekmez; bu değişiklik
            # clone süresini büyük repolarda 10-30x hızlandırır.
            clone_cmd = ["git", "clone", "--depth", "1", project.repo_url, target_dir]
            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Git clone failed (Exit {process.returncode}): {stderr.decode('utf-8')}")

            # 4. Gitleaks Taraması
            import json
            
            report_path = os.path.join(target_dir, "report.json")
            gitleaks_cmd = [
                "gitleaks", "detect",
                "--source", ".",
                "-c", "/app/gitleaks.toml",
                "--report-format", "json",
                "--report-path", report_path,
                "--exit-code", "0"
            ]
            
            gitleaks_process = await asyncio.create_subprocess_exec(
                *gitleaks_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target_dir
            )
            await gitleaks_process.communicate()
            
            vulnerability_objects = []
            
            # Secrets results
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if content.strip():
                        findings = json.loads(content)
                        for finding in findings:
                            vuln = Vulnerability(
                                scan_id=scan.id,
                                tool_vulnerability_id=finding.get("RuleID", "unknown-rule"),
                                severity=Severity.CRITICAL,
                                vulnerability_type="secret-leak",
                                file_path=finding.get("File", "unknown"),
                                line_number=finding.get("StartLine", 0),
                                description=finding.get("Description", "Exposed secret found"),
                                raw_evidence=finding
                            )
                            session.add(vuln)
                            vulnerability_objects.append(vuln)

            # 5. SCA (pip-audit)
            sca_findings = await run_pip_audit(target_dir)
            for f in sca_findings:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    tool_vulnerability_id=f["id"],
                    severity=Severity.HIGH,
                    vulnerability_type="dependency-vulnerability",
                    file_path="requirements.txt",
                    line_number=0,
                    description=f"Vulnerable package: {f['package']}@{f['version']}. {f['description']}",
                    raw_evidence=f
                )
                session.add(vuln)
                vulnerability_objects.append(vuln)

            await session.flush()
            
            # 6. Prepare AI Enrichment Data
            # Deduplication: Her benzersiz kural tipi (tool_vulnerability_id) için
            # yalnızca bir temsilci zafiyet seçilir. Aynı kural tipi için AI analizi
            # her zaman aynı sonucu verir; 182 aynı "aws-access-token" zafiyeti
            # için 182 kez LLM çağırmak yerine 1 kez çağırmak yeterlidir.
            enrichment_data = []
            if not skip_ai:
                seen_rule_ids: set = set()
                for v in vulnerability_objects:
                    if v.severity in [Severity.CRITICAL, Severity.HIGH]:
                        rule_id = v.tool_vulnerability_id or "unknown"
                        if rule_id not in seen_rule_ids:
                            seen_rule_ids.add(rule_id)
                            enrichment_data.append((str(v.id), {
                                "file_path": v.file_path,
                                "description": v.description,
                                "raw_evidence": v.raw_evidence
                            }))

            # 8. Lifecycle Kapat
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.now(timezone.utc)
            scan.logs = f"Scan completed. Found {len(vulnerability_objects)} issues."
            project.last_scan_at = datetime.now(timezone.utc)
            
            await session.commit()
            
            # Progress Update: SUCCESS sinyalini erken gönder
            result_payload = {
                "status": "success", 
                "scan_id": str(scan.id), 
                "vuln_count": len(vulnerability_objects)
            }
            
            # Task objesine erişim (self parametresi üzerinden)
            # Not: async_scan_logic içinde self yok, bu yüzden meta bilgisini return ile döneceğiz
            # veya task status endpoint'inde DB'den bakacağız.
            # Şimdilik architect'in istediği 'Immediate Return' için orchestration.py 
            # commit sonrası result_payload hazırlıyor.

            # Trigger AI Enrichment (Completely Independent Process)
            if enrichment_data:
                trigger_enrichment_batch.delay(enrichment_data)

            return result_payload
            
        except Exception as e:
            await session.rollback()
            if 'scan' in locals() and scan.id:
                scan.status = ScanStatus.FAILED
                scan.finished_at = datetime.now(timezone.utc)
                scan.logs = f"Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}" 
                session.add(scan)
                await session.commit()
            return {"status": "failed", "error": str(e)}
        finally:
            shutil.rmtree(target_dir, ignore_errors=True)

@celery_app.task(bind=True, name="orchestration.run_scan_pipeline", acks_late=True)
def run_scan_pipeline(self, project_id: str, scan_id_str: str, skip_ai: bool = False):
    """
    Celery Task Entry Point
    """
    try:
        result = asyncio.run(async_scan_logic(project_id, scan_id_str, skip_ai))
        return result
    except Exception as e:
        logger.error(f"Task Failed: {str(e)}")
        self.update_state(state='FAILURE', meta={'exc': str(e)})
        raise e
