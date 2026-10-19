FROM python:3.12-slim

# Gerekli işletim sistemi bağımlılıklarını kur (Git clone ve Wget için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    wget \
    tar \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Gitleaks'i sistem seviyesinde binary olarak indir ve kur
ENV GITLEAKS_VERSION="8.18.2"
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && tar -xzf gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && chmod +x /usr/local/bin/gitleaks \
    && rm gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz README.md LICENSE

WORKDIR /app

# Layer caching'den yararlan
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Deep Scan için Semgrep kurulumu (ayrı layer — cache dostu)
RUN pip install --no-cache-dir semgrep

COPY . .

# Import hatalarını önlemek için PYTHONPATH ayarı
ENV PYTHONPATH=/app
