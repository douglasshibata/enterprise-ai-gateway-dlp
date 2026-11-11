import uuid
import time
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Header, Response
from .dlp import DlpInspectionEngine
from .vault import EncryptedSessionVault
from .cache import SemanticCacheEngine
from .telemetry import KafkaTelemetryEmitter

app = FastAPI(
    title="Enterprise AI Gateway & DLP Core",
    description="Edge Ingress, Active DLP Sanitization, Semantic Caching, Secrecy Routing, and Reversible AES-256-GCM Vault.",
    version="1.0.0"
)

dlp_engine = DlpInspectionEngine()
session_vault = EncryptedSessionVault()
cache_engine = SemanticCacheEngine()
telemetry_emitter = KafkaTelemetryEmitter()

class PromptRequest(BaseModel):
    prompt: str
    secrecy_tier: str = "CONFIDENTIAL"  # RESTRICTED, CONFIDENTIAL, PUBLIC
    model: str = "gpt-4o"
    user: str = "employee@corp.internal"
    department: str = "RH"

class GatewayResponse(BaseModel):
    session_id: str
    rehydrated_response: str
    sanitized_prompt: str
    cache_hit: bool
    routed_target: str
    entities_redacted: int

@app.get("/health")
def health():
    return {"status": "healthy", "service": "enterprise-ai-gateway-dlp"}

@app.post("/v1/process-prompt", response_model=GatewayResponse)
def process_prompt(req: PromptRequest, response: Response):
    session_id = str(uuid.uuid4())

    # Step 1: DLP Hard-block check
    is_blocked, reason = dlp_engine.check_hard_blocks(req.prompt)
    if is_blocked:
        telemetry_emitter.emit_audit_event(
            tenant=req.department,
            user=req.user,
            secrecy_tier=req.secrecy_tier,
            cache_hit=False,
            tokens_used=0,
            entities_detected=1,
            target_cloud="BLOCKED"
        )
        raise HTTPException(status_code=403, detail=f"DLP Hard-Block: {reason}")

    # Step 2: DLP Active Sanitization
    sanitized_prompt, token_mapping = dlp_engine.inspect_and_anonymize(req.prompt)
    session_vault.store_mapping(session_id, token_mapping)

    # Step 3: Semantic Cache Lookup
    cached_reply = cache_engine.lookup(sanitized_prompt)
    if cached_reply:
        rehydrated = session_vault.rehydrate_text(session_id, cached_reply)
        telemetry_emitter.emit_audit_event(
            tenant=req.department,
            user=req.user,
            secrecy_tier=req.secrecy_tier,
            cache_hit=True,
            tokens_used=0,
            entities_detected=len(token_mapping),
            target_cloud="SEMANTIC_CACHE"
        )
        response.headers["x-cache-status"] = "HIT"
        return GatewayResponse(
            session_id=session_id,
            rehydrated_response=rehydrated,
            sanitized_prompt=sanitized_prompt,
            cache_hit=True,
            routed_target="SEMANTIC_CACHE",
            entities_redacted=len(token_mapping)
        )

    response.headers["x-cache-status"] = "MISS"

    # Step 4: Secrecy Routing
    if req.secrecy_tier == "RESTRICTED":
        # Keep strictly on-premise air-gapped
        routed_target = "ON_PREMISE_OLLAMA"
        simulated_llm_output = f"[Ollama Llama-3-70B Air-Gapped] Processado com segurança para: {sanitized_prompt}"
    else:
        # Public cloud
        routed_target = "PUBLIC_CLOUD_OPENAI"
        simulated_llm_output = f"[OpenAI GPT-4o Cloud] Resposta executiva para: {sanitized_prompt}"

    # Step 5: Store in cache
    cache_engine.store(sanitized_prompt, simulated_llm_output)

    # Step 6: Re-hydrate response
    rehydrated = session_vault.rehydrate_text(session_id, simulated_llm_output)

    # Step 7: Async Telemetry
    telemetry_emitter.emit_audit_event(
        tenant=req.department,
        user=req.user,
        secrecy_tier=req.secrecy_tier,
        cache_hit=False,
        tokens_used=len(sanitized_prompt.split()) * 2,
        entities_detected=len(token_mapping),
        target_cloud=routed_target
    )

    return GatewayResponse(
        session_id=session_id,
        rehydrated_response=rehydrated,
        sanitized_prompt=sanitized_prompt,
        cache_hit=False,
        routed_target=routed_target,
        entities_redacted=len(token_mapping)
    )
