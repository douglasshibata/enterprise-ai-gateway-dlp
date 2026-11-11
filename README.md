# 🛡️ Enterprise AI Gateway & Data Loss Prevention (DLP)

A production-grade implementation of the master architectural blueprint documented in [`docs/blueprints/ENTERPRISE_AI_GATEWAY_DLP_BLUEPRINT.md`](../docs/blueprints/ENTERPRISE_AI_GATEWAY_DLP_BLUEPRINT.md).

---

## 🏛️ Architecture & Capabilities

1. **Active DLP Inspection & Hard-Block Enforcer:**
   - Detects and rejects high-entropy secrets (Shannon H > 4.5), database strings, and private cryptographic keys.
   - Deterministic sanitization of Brazilian CPF, credit cards (Luhn algorithm), and emails.
2. **Reversible Tokenization Vault:**
   - AES-256-GCM encryption with session-scoped 24h TTL. Re-hydrates responses before returning to authenticated callers.
3. **Semantic Caching Engine:**
   - Cosine similarity matching over normalized embeddings, delivering instant cache hits at $0.00 cost.
4. **Secrecy Tier Routing:**
   - Keeps `RESTRICTED` queries within on-premise air-gapped models (e.g. Ollama/vLLM) and routes `CONFIDENTIAL`/`PUBLIC` to approved cloud providers.
5. **Kafka Telemetry Emitting:**
   - Asynchronous audit event dispatching for FinOps monitoring.

---

## 🧪 Testing

```bash
PYTHONPATH=enterprise-ai-gateway-dlp pytest enterprise-ai-gateway-dlp/tests/ -v
```
