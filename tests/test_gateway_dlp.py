import pytest
from fastapi.testclient import TestClient
from src.main import app, telemetry_emitter
from src.dlp import DlpInspectionEngine, calculate_shannon_entropy, validate_cpf, validate_luhn
from src.vault import EncryptedSessionVault

client = TestClient(app)

def test_cpf_validator():
    # 123.456.789-09 happens to have valid check digits (d1=0, d2=9)
    assert validate_cpf("123.456.789-09") is True
    # Invalid check digits
    assert validate_cpf("123.456.789-00") is False
    # Identical digits are invalid
    assert validate_cpf("111.111.111-11") is False

def test_luhn_validator():
    # Valid Visa test number
    assert validate_luhn("4532015112830366") is True
    # Invalid card number
    assert validate_luhn("4532015112830367") is False

def test_shannon_entropy():
    low_entropy = "aaaaaabbbbbb"
    high_entropy = "k8s_x9qA!7z$L0m#P2w@"
    assert calculate_shannon_entropy(low_entropy) < 2.0
    assert calculate_shannon_entropy(high_entropy) > 3.8

def test_encrypted_session_vault():
    vault = EncryptedSessionVault()
    mapping = {"[CPF_1]": "123.456.789-01", "[NAME_1]": "Carlos Silva"}
    vault.store_mapping("sess-1", mapping)

    text = "Plano para [NAME_1] portador do [CPF_1]."
    rehydrated = vault.rehydrate_text("sess-1", text)
    assert rehydrated == "Plano para Carlos Silva portador do 123.456.789-01."

def test_hard_block_private_key():
    req = {
        "prompt": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
        "department": "IT"
    }
    res = client.post("/v1/process-prompt", json=req)
    assert res.status_code == 403
    assert "DLP Hard-Block" in res.json()["detail"]

def test_prompt_processing_and_cache():
    req = {
        "prompt": "Elabore um PDI para o analista contato contato@empresa.com",
        "secrecy_tier": "CONFIDENTIAL",
        "department": "RH",
        "user": "rh@empresa.com"
    }
    res1 = client.post("/v1/process-prompt", json=req)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["cache_hit"] is False
    assert "[EMAIL_1]" in data1["sanitized_prompt"]
    assert "contato@empresa.com" in data1["rehydrated_response"]
    assert data1["routed_target"] == "PUBLIC_CLOUD_OPENAI"

    # Second call should be a cache hit
    res2 = client.post("/v1/process-prompt", json=req)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["cache_hit"] is True
    assert data2["routed_target"] == "SEMANTIC_CACHE"

def test_secrecy_routing_restricted():
    req = {
        "prompt": "Análise restrita de patentes internas",
        "secrecy_tier": "RESTRICTED",
        "department": "Legal",
        "user": "legal@empresa.com"
    }
    res = client.post("/v1/process-prompt", json=req)
    assert res.status_code == 200
    assert res.json()["routed_target"] == "ON_PREMISE_OLLAMA"
