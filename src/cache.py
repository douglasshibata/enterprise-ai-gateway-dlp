import math
import hashlib
from typing import Dict, Any, Optional, Tuple, List

class SemanticCacheEngine:
    """
    Redis HNSW vector search semantic cache simulator.
    Uses cosine distance threshold (default <= 0.15) to identify semantic equivalence.
    """
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self.cache: List[Dict[str, Any]] = []

    def _pseudo_embed(self, text: str) -> List[float]:
        # Deterministic 16-dim normalized vector based on character frequencies & sha256
        h = hashlib.sha256(text.lower().strip().encode("utf-8")).digest()
        raw_vec = [float(b) for b in h[:16]]
        norm = math.sqrt(sum(x * x for x in raw_vec)) or 1.0
        return [x / norm for x in raw_vec]

    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        return sum(a * b for a, b in zip(v1, v2))

    def lookup(self, sanitized_prompt: str) -> Optional[str]:
        target_vec = self._pseudo_embed(sanitized_prompt)
        for entry in self.cache:
            sim = self._cosine_similarity(target_vec, entry["embedding"])
            if sim >= self.similarity_threshold:
                return entry["response"]
        return None

    def store(self, sanitized_prompt: str, response: str):
        vec = self._pseudo_embed(sanitized_prompt)
        self.cache.append({
            "prompt": sanitized_prompt,
            "embedding": vec,
            "response": response
        })
