# 📘 Tutorial do Enterprise AI Gateway & DLP

Este guia orienta a utilização do gateway de privacidade com sanitização DLP, cofre criptográfico AES-256-GCM e roteamento por sigilo.

---

## 1. Instalação e Execução

```bash
cd enterprise-ai-gateway-dlp
pip install -r requirements.txt
uvicorn src.main:app --port 8000
```

---

## 2. Exemplos de Requisições

### Enviando Prompt com Dados Pessoais (Sanitização e Re-hidratação)
```bash
curl -X POST http://localhost:8000/v1/process-prompt \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Elabore plano para o colaborador contato joao@empresa.com",
    "secrecy_tier": "CONFIDENTIAL",
    "department": "RH",
    "user": "rh@empresa.com"
  }'
```

---

## 3. Executando os Testes Automatizados

```bash
PYTHONPATH=enterprise-ai-gateway-dlp pytest enterprise-ai-gateway-dlp/tests/ -v
```
