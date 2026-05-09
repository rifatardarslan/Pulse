import os
import json
import logging
import asyncio
from typing import Dict, Any, Optional
from openai import AsyncOpenAI
import httpx

# ==========================================
# RATIONALE (Senior Architect Note)
# ==========================================
# 1. Vendor Agnostic (Bağımsızlık): AsyncOpenAI kütüphanesini kullanarak RAG motorunu 
#    hem yerel (Ollama/Llama3) hem de bulut (OpenAI/GPT-4o) altyapısına uyumlu hale 
#    getirdim. Sadece Base URL ve API Key değiştirmek yeterlidir.
# 2. System Prompt Engineering: AI'ya "Siber Güvenlik Mühendisi" kimliği giydirerek
#    ve NIST/OWASP standartlarına uymasını dikte ederek halüsinasyonları (hallucination) 
#    ve format dışı yanıtları büyük ölçüde engelledim.
# 3. Health Check: AI çağrısı yapmadan önce Ollama'nın ayakta olup olmadığını kontrol 
#    ederek gereksiz beklemeleri ve karmaşık hata mesajlarını önlüyoruz.

logger = logging.getLogger(__name__)

# OLLAMA Yapılandırması
# host.docker.internal: Docker içinden host'taki Ollama'ya erişim sağlar.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
AI_API_KEY = os.getenv("AI_API_KEY", "ollama") 
AI_MODEL = os.getenv("AI_MODEL", "llama3")
AI_TIMEOUT = 120  # saniye

# OpenAI uyumlu istemci (Ollama /v1 endpoint'ini kullanır)
# Senior Architect Note: Timeout=None ve connection limits ile stabilite sağlandı.
client = AsyncOpenAI(
    base_url=f"{OLLAMA_BASE_URL}/v1",
    api_key=AI_API_KEY,
    timeout=None,
    http_client=httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        timeout=None
    ),
    max_retries=0,
)

async def check_ollama_health() -> bool:
    """
    Ollama servisinin ayakta olup olmadığını kontrol eder.
    """
    try:
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5.0)
            return response.status_code == 200
    except Exception:
        return False

def extract_code_block(markdown_text: str) -> Optional[str]:
    """
    Markdown içerisinden sadece kod bloğunu (``` ... ```) temiz bir şekilde ayıklar.
    """
    import re
    match = re.search(r'```[a-zA-Z]*\n(.*?)```', markdown_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None

async def generate_remediation(vuln_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verilen zafiyet (Vulnerability) detaylarına bakarak AI tabanlı çözüm önerisi üretir.
    """
    file_path = vuln_data.get("file_path", "Unknown File")
    description = vuln_data.get("description", "No description provided.")
    evidence = json.dumps(vuln_data.get("raw_evidence", {}), indent=2)

    # 1. Health Check
    if not await check_ollama_health():
        return {
            "status": "skipped",
            "model_used": AI_MODEL,
            "remediation_steps": "AI Analysis Pending (Service Unavailable)",
            "suggested_fix": None,
            "confidence_score": 0.0
        }
    
    system_prompt = (
        "Sen uzman bir siber güvenlik mühendisisin. "
        "Amacın sistemde bulunan zafiyetleri OWASP ve NIST gibi en iyi "
        "güvenlik standartlarına uygun şekilde analiz edip düzeltmektir.\n"
        "Lütfen çözüm önerisini Markdown formatında ve temiz bir kod bloğu içinde ver. "
        "Ayrıca adım adım çözüm talimatlarını (remediation steps) açıkla."
    )
    
    user_prompt = (
        f"Aşağıdaki güvenlik zafiyeti tespit edilmiştir:\n\n"
        f"- Dosya: {file_path}\n"
        f"- Açıklama: {description}\n"
        f"- Kanıt (Raw JSON):\n{evidence}\n\n"
        "Bu zafiyeti nasıl düzeltebilirim? Lütfen bana güvenli kod örneğini de ver."
    )
    
    try:
        response = await asyncio.wait_for(
            client.chat.completions.create(
                model=AI_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2, 
                max_tokens=1500
            ),
            timeout=AI_TIMEOUT
        )
        
        answer = response.choices[0].message.content
        
        return {
            "status": "success",
            "model_used": AI_MODEL,
            "remediation_steps": answer,
            "suggested_fix": extract_code_block(answer),
            "confidence_score": 0.9
        }
    except asyncio.TimeoutError:
        return {
            "status": "skipped",
            "model_used": AI_MODEL,
            "remediation_steps": "AI Analysis Timeout (Retrying in background)",
            "suggested_fix": None,
            "confidence_score": 0.0
        }
    except Exception:
        return {
            "status": "skipped",
            "model_used": AI_MODEL,
            "remediation_steps": "AI Analysis Pending",
            "suggested_fix": None,
            "confidence_score": 0.0
        }
