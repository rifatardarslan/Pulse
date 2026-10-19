# Pulse — AI-Powered Security Analysis Pipeline

```
      ___       __
     / _ \__ __/ /__ ___
    / ___/ // / (_-</ -_)
   /_/   \_,_/_/___/\__/

  AI-Driven Vulnerability Analysis & Remediation  v2.0.0
```

Pulse, kod depolarını otomatik tarayan, bulunan güvenlik açıklarını veritabanında saklayan ve her benzersiz zafiyet tipi için **LLM tabanlı düzeltme önerileri** üreten bir güvenlik analiz pipeline'ıdır.

---

## Özellikler

| Özellik | Detay |
|---------|-------|
| **Secret Scanning** | Gitleaks ile 400+ regex kuralı — API key, token, parola tespiti |
| **SAST Analizi** | Semgrep `--config auto` ile kod düzeyinde güvenlik açığı tespiti |
| **Dependency Audit** | pip-audit ile Python paketlerindeki bilinen CVE'leri bulur |
| **AI Remediation** | Ollama/Llama3 (veya GPT-4o uyumlu) ile otomatik düzeltme önerisi |
| **AI Kod Bağlamı** | Bulgular etrafındaki ±5 satır kod AI prompt'a eklenir — daha hassas öneriler |
| **False Positive Yönetimi** | CLI'dan FP işaretleme; diff ve raporlarda FP'ler ayrıştırılır |
| **Scan Diff** | Aynı repo'nun ardışık taramaları arasında yeni/düzeltilmiş/devam eden ayrımı |
| **Webhook Bildirimleri** | Tarama tamamlanınca POST — generic JSON + Slack Blocks formatı |
| **HTML Raporu** | Jinja2 ile dark-theme rapor; özet, bulgular tablosu, FP bölümü, AI analizleri |
| **Zamanlanmış Taramalar** | Celery Beat + cron ifadeleri; CLI'dan oluştur/duraklat/sil |
| **API Key Auth** | `X-API-Key` header ile tüm endpoint'ler korunur |
| **CI/CD Plugin** | GitHub Actions composite action — tetikle → bekle → CRITICAL'da CI'ı durdur |
| **Fire-and-Forget** | Celery kuyruğu — tarama API'yi bloke etmez, sonuçlar DB'ye yazılır |
| **Deduplication** | Aynı kural tipi için tek AI analizi — 390 task yerine 41 task |
| **Dual Worker** | Scan ve AI kuyruğu ayrı — AI enrichment yeni taramayı bloke etmez |

---

## Mimari

```
+-----------+     POST /scans/      +--------------+
|   CLI     | --------------------> |  FastAPI App  |
| (Rich TUI)| <-- scan_id + 202 --- |  Port 8000    |
+-----------+                       +------+-------+
      |  polls GET /scans/{id}             | .delay()
      |                            +-------v-----------+
      |                            |   Redis Broker     |
      |                            |  +------+ +-----+  |
      |                            |  |scans | | ai  |  |
      |                            |  +--+---+ +--+--+  |
      |                            +-----+---------+----+
      |                                  |         |
      |                   +--------------+    +----+--------+
      |                   |                   |             |
      |            +------v----+    +----------v--+  +------v------+
      |            |  Worker   |    |  Worker-AI  |  |    Beat     |
      |            |  (scans)  |    |  (ai)       |  | (schedules) |
      |            | git clone |    | LLM calls   |  | croniter    |
      |            | gitleaks  |    | Ollama/GPT  |  +------+------+
      |            | semgrep   |    +-------------+         |
      |            | pip-audit |                            | creates scans
      |            +----+------+                            |
      |                 | writes                            |
      |          +------v--------+<--------------------------+
      +-- view ->|  PostgreSQL   |
                 |  (results)    |
                 +---------------+
```

---

## Teknoloji Yığını

| Katman | Teknoloji |
|--------|-----------|
| API Gateway | FastAPI 0.115+ (async) |
| Task Queue | Celery 5.3 + Redis 7 |
| Scheduler | Celery Beat + croniter |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 + asyncpg |
| Migrations | Alembic 1.13+ |
| Security Engines | Gitleaks 8.18.2, Semgrep (auto), pip-audit 2.7.3 |
| AI Engine | OpenAI SDK — Ollama/Llama3 veya GPT-4o uyumlu |
| Reporting | Jinja2 3.1+ |
| CLI | Typer + Rich |
| Infrastructure | Docker + Docker Compose |

---

## Kurulum

### Gereksinimler

- **Docker Desktop** (v24+)
- **Ollama** — yerel AI analizi için (opsiyonel, GPT-4o da kullanılabilir)

```bash
# Ollama kurulumu sonrası modeli çekin
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

Üretim için kritik değişkenler:

```env
# API koruması — boş bırakılırsa dev modunda (tüm istekler kabul edilir)
PULSE_API_KEY=gizli-bir-anahtar

# Webhook — boş bırakılırsa devre dışı
WEBHOOK_URL=https://hooks.slack.com/services/...

# GPT-4o kullanmak için:
OLLAMA_BASE_URL=https://api.openai.com
AI_API_KEY=sk-...
AI_MODEL=gpt-4o
```

**3. Sistemi başlatın:**

```bash
docker compose up -d --build
```

Bu komut 6 servisi ayağa kaldırır:

| Servis | Açıklama |
|--------|----------|
| `pulse_db` | PostgreSQL 16 |
| `pulse_redis` | Redis 7 |
| `pulse_app` | FastAPI — port 8000 (Alembic migration → uvicorn) |
| `pulse_worker` | Scan pipeline worker (Gitleaks + Semgrep + pip-audit) |
| `pulse_worker_ai` | AI enrichment worker |
| `pulse_beat` | Celery Beat — zamanlanmış tarama tetikleyici |

> **Not:** `pulse_app` başlarken `alembic upgrade head` çalıştırır. Yeni ve mevcut V1 veritabanları otomatik migrate edilir.

**4. CLI'ı kurun (opsiyonel):**

```bash
pip install -e .
```

---

## Kullanım

### İnteraktif CLI

```bash
# Python ile doğrudan:
python -m app.cli

# pip install -e . yaptıysanız:
pulse
```

```
  [1] Full Scan  (Gitleaks + Semgrep + pip-audit + AI)
  [2] Quick Scan (No AI)
  [3] View Past Scans (History)
  [4] Scheduled Scans
  [5] Help
  [6] Quit
```

**Tarama akışı:**

1. `[1]` → GitHub URL veya yerel dizin girin
2. Tarama tamamlanınca sayfalı zafiyet listesi açılır (20 zafiyet/sayfa, FP rozeti dahil)
3. Bir **numara** yazın → AI analizi ve kod bağlamı ekranı
4. `[F]` → False Positive işaretle, `[U]` → işareti kaldır
5. `[D]` → önceki taramayla diff, `[E]` → HTML rapor kaydet
6. `N` / `P` ile sayfalar arası geçiş, `Q` ile çıkış

**Zamanlanmış Taramalar (`[4]`):**

```
  [C]reate  — yeni zamanlama oluştur (cron ifadesi ile)
  [P]ause   — duraklatı
  [R]esume  — devam ettir
  [D]elete  — sil
  [T]rigger — şimdi tetikle
  [Q]uit
```

### REST API

Swagger UI: `http://localhost:8000/docs`

Tüm endpoint'ler `X-API-Key` header gerektirir (`PULSE_API_KEY` boşsa dev modunda gerekmiyor).

**Scan Endpoint'leri:**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/health` | Liveness probe |
| POST | `/api/v1/scans/` | Yeni tarama başlat |
| GET | `/api/v1/scans/all` | Tüm taramaları listele (son 50) |
| GET | `/api/v1/scans/{id}` | Tarama durumu |
| GET | `/api/v1/scans/{id}/results` | Zafiyet + AI sonuçları |
| PATCH | `/api/v1/scans/{scan_id}/vulnerabilities/{vuln_id}/false-positive` | FP toggle |
| GET | `/api/v1/scans/{id}/false-positives` | FP zafiyet listesi |
| GET | `/api/v1/scans/{id}/diff` | Önceki taramayla diff |
| GET | `/api/v1/scans/{id}/diff/{other_id}` | Belirli iki tarama arası diff |
| GET | `/api/v1/scans/{id}/report` | HTML rapor indir |

**Schedule Endpoint'leri:**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/v1/schedules/` | Zamanlama oluştur |
| GET | `/api/v1/schedules/` | Tüm zamanlamaları listele |
| GET | `/api/v1/schedules/{id}` | Tek zamanlama |
| PATCH | `/api/v1/schedules/{id}` | Güncelle (duraklat/devam/cron değiştir) |
| DELETE | `/api/v1/schedules/{id}` | Sil |
| POST | `/api/v1/schedules/{id}/run` | Şimdi tetikle |

```bash
# API key ile tarama başlat
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PULSE_API_KEY" \
  -d '{"repo_url": "https://github.com/org/repo", "skip_ai": false}'

# HTML raporu kaydet
curl -H "X-API-Key: $PULSE_API_KEY" \
  http://localhost:8000/api/v1/scans/<scan_id>/report -o report.html

# Günlük zamanlama oluştur
curl -X POST http://localhost:8000/api/v1/schedules/ \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PULSE_API_KEY" \
  -d '{"repo_url": "https://github.com/org/repo", "cron_expression": "0 2 * * *"}'
```

---

## CI/CD Entegrasyonu

Pulse, GitHub Actions için hazır bir composite action içerir.

```yaml
# .github/workflows/security.yml
jobs:
  pulse-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/pulse-scan
        with:
          api_url: ${{ secrets.PULSE_API_URL }}
          api_key: ${{ secrets.PULSE_API_KEY }}
          repo_url: ${{ github.server_url }}/${{ github.repository }}
          fail_on_critical: "true"
          export_report: "true"
```

Action CRITICAL bulgu tespit ederse CI'ı durdurur ve HTML raporu artifact olarak yükler.

---

## Veri Modeli

```
Project  (repo bilgisi, webhook_url)
  ├── Scan      (tarama çalıştırması, scanners_run JSONB)
  │     └── Vulnerability  (bulgu; is_false_positive, false_positive_reason)
  │               └── Remediation  (AI düzeltme önerisi)
  └── Schedule  (cron zamanlaması, ACTIVE|PAUSED|ERROR)
```

---

## Konfigürasyon

| Env Var | Varsayılan | Açıklama |
|---------|-----------|----------|
| `DATABASE_URL` | `postgresql+asyncpg://pulse:pulse123@db:5432/pulse` | PostgreSQL bağlantı URL'si |
| `REDIS_URL` | `redis://redis:6379/0` | Redis broker URL'si |
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | Ollama endpoint |
| `AI_MODEL` | `llama3` | Kullanılacak LLM modeli |
| `AI_API_KEY` | `ollama` | OpenAI uyumlu API key |
| `PULSE_API_KEY` | _(boş)_ | API koruma anahtarı; boşsa dev modu |
| `WEBHOOK_URL` | _(boş)_ | Scan tamamlandığında POST URL'si |
| `WEBHOOK_TIMEOUT` | `10` | Webhook isteği timeout (saniye) |

---

## Geliştirme

```bash
# Logları izle
docker compose logs -f worker worker-ai beat

# API'yi yeniden başlat (kod değişikliği sonrası)
docker compose restart app

# Migration durumunu kontrol et
docker compose exec app alembic current

# Redis kuyruğunu temizle (geliştirme sırasında)
docker compose exec redis redis-cli FLUSHDB
```

---

## Lisans

Bu proje [MIT](LICENSE) lisansı altında lisanslanmıştır.

---

Developed by **Rifat Arda Arslan** — 2026
