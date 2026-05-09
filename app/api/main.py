from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as scan_router

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. API Gateway Configuration: FastAPI'nin ana entry point dosyasıdır.
# 2. CORS Policies (Cross-Origin Resource Sharing): Pulse'un ileride bir React
#    veya Vue.js tabanlı arayüzü (Dashboard) olacağı için, farklı bir port/domain 
#    üzerinden gelen API isteklerini engellememesi adına CORS ayarları eklendi.
# 3. Lifespan: FastAPI'nin modern yaşam döngüsü yönetimi. on_startup yerine
#    asynccontextmanager kullanılarak DB tabloları uygulama başlarken oluşturulur.

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlarken DB tablolarını oluştur, kapanırken temizlik yap."""
    from app.core.database import init_db, engine
    
    # Veritabanı tablolarını oluştur
    await init_db()
    
    yield  # Uygulama çalışıyor
    
    # Shutdown: Engine bağlantılarını temizle
    await engine.dispose()

app = FastAPI(
    title="Pulse SecOps API",
    description="AI-Driven Vulnerability Analysis & Remediation Pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware Ayarları
app.add_middleware(
    CORSMiddleware,
    # TODO: Production aşamasında "allow_origins" içine sadece frontend domaini yazılmalıdır.
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rotaları (Endpoints) API Gateway'e dahil et
app.include_router(scan_router, prefix="/api/v1/scans", tags=["Scans"])

@app.get("/health", tags=["System"])
async def health_check():
    """
    Kubernetes veya Docker Swarm load balancer'ları için Liveness/Readiness Probe kontrolü.
    """
    return {"status": "ok", "service": "Pulse API Gateway", "version": "1.0.0"}

