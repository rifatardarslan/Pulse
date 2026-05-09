import os
from celery import Celery

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Broker & Backend: Redis, in-memory yapısı sayesinde Celery görevlerinin 
#    (task queue) çok hızlı iletilmesini sağlar. Ayrıca `backend` olarak da 
#    kullanarak task'ın sonucunu (başarılı/başarısız) yine Redis'te tutuyoruz.
# 2. Yatay Ölçeklenebilirlik (Horizontal Scaling): "pulse_worker" ismindeki bu app,
#    istenirse 10 farklı sunucuda aynı anda çalıştırılabilir (Worker cluster). 
#    Hepsi aynı Redis'e bağlanarak "Gitleaks Scan" iş yükünü (load) paylaşır.
# 3. Fairness (Adil Dağıtım): `worker_prefetch_multiplier=1` ayarı, uzun süren 
#    tarama işlemlerinde tek bir worker'ın tüm işleri üstüne alıp şişmesini engeller; 
#    işler boştaki worker'lara adil dağılır.

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "pulse_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.orchestration"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_soft_time_limit=3600,
    task_time_limit=3660,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    # Scan pipeline tasks go to high-priority 'scans' queue;
    # AI enrichment goes to 'ai' queue so it never blocks new scans.
    task_routes={
        "orchestration.run_scan_pipeline": {"queue": "scans"},
        "orchestration.trigger_enrichment_batch": {"queue": "ai"},
        "orchestration.process_ai_enrichment": {"queue": "ai"},
    },
    task_default_queue="scans",
)
