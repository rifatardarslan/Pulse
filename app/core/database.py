import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# Pulse gibi yüksek I/O ve concurrency (eşzamanlılık) gerektiren bir sistemde
# senkron DB işlemleri event loop'u bloklayarak darboğaz yaratır. Bu yüzden
# asyncpg sürücüsü ile asenkron SQLAlchemy (v2.0+) kullanıyoruz.
# async_sessionmaker ve dependency injection (get_db) yapısı sayesinde 
# FastAPI endpoint'leri veya Celery worker'ları connection leak (bağlantı sızıntısı) 
# yaratmadan güvenle veritabanına erişebilir.

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/pulse")

from sqlalchemy.pool import NullPool

# Echo=False production'da log kirliliğini önler, future=True SQLAlchemy 2.0 stili için.
engine = create_async_engine(DATABASE_URL, echo=False, future=True, poolclass=NullPool)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# Celery'nin 'prefork' modunda çalışan worker'lar ebeveyn sürecin (parent process) belleğini kopyalar.
# Eğer veritabanı bağlantı havuzu (connection pool) ebeveyn süreçte başlatılıp kopyalanırsa,
# worker'lar aynı socket üzerinden işlem yapmaya çalışır. Bu durum "RuntimeError: attached to a different loop"
# ve "InterfaceError: cannot perform operation" hatalarına yol açar.
# Bu yüzden Celery'nin `celeryd_init` / `worker_process_init` sinyali dinlenerek, her worker kendi
# taze ve izole AsyncSession havuzunu sıfırdan kurar.

try:
    from celery.signals import worker_process_init
    from sqlalchemy.pool import NullPool

    @worker_process_init.connect
    def celery_init_db_engine(**kwargs):
        global engine, AsyncSessionLocal
        if engine:
            engine.sync_engine.dispose()
        
        engine = create_async_engine(DATABASE_URL, echo=False, future=True, poolclass=NullPool)
        AsyncSessionLocal = async_sessionmaker(
            bind=engine, 
            class_=AsyncSession, 
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
except ImportError:
    pass

Base = declarative_base()

async def init_db():
    """
    Veritabanı tablolarını oluşturur.
    """
    # Modelleri burada import ediyoruz ki Base.metadata tarafından görülebilsinler
    import app.models.project
    import app.models.scan
    import app.models.vulnerability
    import app.models.remediation
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Provides a transactional scope around a series of operations.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
