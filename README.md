<![CDATA[# Pulse — AI-Powered Security Analysis Pipeline

```
      ___       __
     / _ \__ __/ /__ ___
    / ___/ // / (_-</ -_)
   /_/   \_,_/_/___/\__/

  AI-Driven Vulnerability Analysis & Remediation
```

Pulse, kod depolarını otomatik tarayan, bulunan güvenlik açıklarını veritabanında saklayan ve her benzersiz zafiyet tipi için **LLM tabanlı düzeltme önerileri** üreten bir güvenlik analiz pipeline'ıdır.

---

## Özellikler

| Özellik | Detay |
|---------|-------|
| **Secret Scanning** | Gitleaks ile 400+ regex kuralı — API key, token, parola tespiti |
| **Dependency Audit** | pip-audit ile Python paketlerindeki bilinen CVE'leri bulur |
| **AI Remediation** | Ollama/Llama3 (veya GPT-4o uyumlu) ile otomatik düzeltme önerisi |
| **Fire-and-Forget** | Celery kuyruğu — tarama API'yi bloke etmez, sonuçlar DB'ye yazılır |
| **Paginated CLI** | Sayfalı zafiyet listesi, History drill-down, AI detay ekranı |
| **Deduplication** | Aynı kural tipi için tek AI analizi — 390 task yerine 41 task |
| **Dual Worker** | Scan ve AI kuyruğu ayrı — AI enrichment hiçbir zaman yeni taramayı bloke etmez |

---

## Mimari

```
┌─────────────┐     POST /scans/      ┌──────────────┐
│   CLI       │ ──────────────────▶  │  FastAPI App  │
│  (Rich TUI) │ ◀── scan_id + 202 ── │  Port 8000    │
└─────────────┘                       └──────┬───────┘
      │  polls GET /scans/{id}               │ .delay()
      │                              ┌───────▼────────────┐
      │                              │   Redis Broker      │
      │                              │  ┌──────┐ ┌─────┐  │
      │                              │  │scans │ │ ai  │  │
      │                              │  └──┬───┘ └──┬──┘  │
      │                              └─────┼────────┼──────┘
      │                                    │        │
      │                           ┌────────▼─┐  ┌───▼────────┐
      │                           │  Worker   │  │  Worker-AI  │
      │                           │  (scans)  │  │  (ai)       │
      │                           │ git clone │  │ LLM calls   │
      │                           │ gitleaks  │  │ Ollama/GPT  │
      │                           │ pip-audit │  └─────────────┘
      │                           └────┬──────┘
      │                                │ writes
      │                         ┌──────▼───────┐
      └─────────────────────────│  PostgreSQL   │
                                │  (results)    │
                                └───────────────┘
```

---

## Teknoloji Yığını

| Katman | Teknoloji |
|--------|-----------|
| API Gateway | FastAPI 0.115+ (async) |
| Task Queue | Celery 5.3 + Redis 7 |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 + asyncpg |
| Security Engines | Gitleaks 8.18.2, pip-audit 2.7.3 |
| AI Engine | OpenAI SDK → Ollama/Llama3 veya GPT-4o |
| CLI | Typer + Rich |
| Infrastructure | Docker + Docker Compose |

---

## Kurulum

### Gereksinimler

- **Docker Desktop** (v24+)
- **Ollama** — yerel AI analizi için (opsiyonel, GPT-4o da kullanılabilir)

```bash
# Ollama kurulumu (Windows/macOS)
# https://ollama.com adresinden indirin
ollama pull llama3
```

### Adımlar

**1. Repoyu klonlayın:**

```bash
git clone https://github.com/rifatardaarslan/pulse.git
cd pulse
```

**2. Ortam değişkenlerini ayarlayın:**

```bash
cp .env.example .env
```

`.env` dosyasını açıp gerekirse düzenleyin (varsayılan değerler geliştirme ortamı için uygundur):

```env
DATABASE_URL=postgresql+asyncpg://pulse:pulse123@db:5432/pulse
REDIS_URL=redis://redis:6379/0
OLLAMA_BASE_URL=http://host.docker.internal:11434
AI_MODEL=llama3
```

**3. Sistemi başlatın:**

```bash
docker compose up -d --build
```

Bu komut 5 servisi ayağa kaldırır:
- `pulse_db` — PostgreSQL
- `pulse_redis` — Redis
- `pulse_app` — FastAPI (port 8000)
- `pulse_worker` — Scan pipeline worker
- `pulse_worker_ai` — AI enrichment worker

**4. CLI'ı kurun (opsiyonel — `pulse` komutu olarak çalıştırmak için):**

```bash
pip install -e .
```

---

## Kullanım

### CLI (Interaktif Menü)

```bash
# Doğrudan Python ile:
python -m app.cli

# pip install -e . yaptıysanız:
pulse
```

```
      ___       __
     / _ \__ __/ /__ ___
    / ___/ // / (_-</ -_)
   /_/   \_,_/_/___/\__/

  Pulse Security Intelligence System v1.0.0 [STABLE]

  ╭─── Interactive Menu ──────────────────╮
  │  [1] Full Scan (Secrets + Libraries + AI)  │
  │  [2] Quick Scan (No AI)                    │
  │  [3] View Past Scans (History)             │
  │  [4] Help                                  │
  │  [5] Quit                                  │
  ╰────────────────────────────────────────────╯
```

**Full Scan akışı:**

1. `[1]` seç → GitHub URL veya yerel dizin gir
2. Tarama ~3-10 saniyede tamamlanır (`--depth 1` ile hızlı clone)
3. Sayfalı zafiyet listesi açılır (20 zafiyet/sayfa)
4. Bir numara yaz → o zafiyetin AI analizi ve önerilen kod düzeltmesi
5. `N` / `P` ile sayfalar arası geçiş, `Q` ile çıkış

**History drill-down:**

1. `[3]` seç → geçmiş taramaları listele
2. Bir numara yaz → o scan'ın zafiyet listesine gir
3. Zafiyet numarası yaz → AI analizi detayını görüntüle

### REST API

API dokümantasyonu: `http://localhost:8000/docs`

| Endpoint | Method | Açıklama |
|----------|--------|----------|
| `/health` | GET | Liveness probe |
| `/api/v1/scans/` | POST | Yeni tarama başlat (fire-and-forget) |
| `/api/v1/scans/all` | GET | Tüm taramaları listele (son 50) |
| `/api/v1/scans/{id}` | GET | Tarama durumu |
| `/api/v1/scans/{id}/results` | GET | Zafiyet + AI sonuçları |
| `/api/v1/scans/status/{task_id}` | GET | Celery task durumu |

**Örnek:**

```bash
# Tarama başlat
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/org/repo", "skip_ai": false}'

# Sonucu sorgula
curl http://localhost:8000/api/v1/scans/<scan_id>/results
```

---

## Veri Modeli

```
Project  (repo bilgisi)
  └── Scan  (her tarama çalıştırması)
        └── Vulnerability  (bulunan zafiyet — Gitleaks/pip-audit)
              └── Remediation  (AI üretilen düzeltme önerisi)
```

- **UUID primary key** — IDOR saldırılarına karşı
- **JSONB `raw_evidence`** — farklı scanner çıktı formatlarını esnek saklar
- **Cascade delete** — Project silinince tüm alt kayıtlar temizlenir

---

## Konfigürasyon

| Env Var | Varsayılan | Açıklama |
|---------|-----------|----------|
| `DATABASE_URL` | `postgresql+asyncpg://pulse:pulse123@db:5432/pulse` | PostgreSQL bağlantı URL'si |
| `REDIS_URL` | `redis://redis:6379/0` | Redis broker URL'si |
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | Ollama endpoint |
| `AI_MODEL` | `llama3` | Kullanılacak LLM modeli |
| `AI_API_KEY` | `ollama` | OpenAI uyumlu API key (Ollama için herhangi bir değer) |

---

## Geliştirme

```bash
# Logları izle
docker compose logs -f worker worker-ai

# Sadece API'yi yeniden başlat (kod değişikliği sonrası)
docker compose restart app

# Veritabanı tablolarını manuel oluştur
python init_db.py

# Redis kuyruğunu temizle (geliştirme sırasında)
docker compose exec redis redis-cli FLUSHDB
```

---

## Gelecek Planları

- [ ] **Web Dashboard** — React tabanlı tarama geçmişi ve istatistik arayüzü
- [ ] **Slack & Teams Entegrasyonu** — Kritik bulgularda anlık bildirim
- [ ] **CI/CD Plugin** — GitHub Actions ve GitLab CI pipeline adımları
- [ ] **Semgrep SAST** — Ek statik analiz motoru desteği
- [ ] **HTML Raporu** — Tarama sonuçlarını dışa aktarma

---

## Lisans

Bu proje [MIT](LICENSE) lisansı altında lisanslanmıştır.

---

Developed by **Rifat Arda Arslan** — 2026
]]>