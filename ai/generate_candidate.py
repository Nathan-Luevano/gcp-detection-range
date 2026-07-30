import json
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "gemma4:26b"


def generate_candidate(prompt):
    payload = json.dumps({"model": MODEL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        result = json.loads(resp.read())
    return result["response"]
