#!/usr/bin/env python3
"""
Pushes GitHub Actions secrets to the KB repo using the GitHub API.
Reads values from ../.env and encrypts them with the repo's public key.

Usage:
    python setup_secrets.py
"""
from __future__ import annotations
import base64, json, os
from pathlib import Path
import urllib.request
import urllib.error
from nacl import encoding, public
from dotenv import load_dotenv

# --------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent.resolve()
load_dotenv(ROOT / ".env")

GITHUB_PAT   = os.environ["GITHUB_PAT"]
REPO         = "TH3-D3V3L0P3R/my-knowledge-base"
API_BASE     = "https://api.github.com"
HEADERS      = {
    "Authorization": f"Bearer {GITHUB_PAT}",
    "Accept":        "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type":  "application/json",
    "User-Agent":    "kb-setup-secrets",
}

SECRETS = {
    "ANTHROPIC_API_KEY": os.environ["ANTHROPIC_API_KEY"],
    "AGENT_ID":          os.environ["AGENT_ID"],
    "AGENT_VERSION":     os.environ["AGENT_VERSION"],
    "ENV_ID":            os.environ["ENV_ID"],
    "SEED_FILE_IDS":     os.environ["SEED_FILE_IDS"],
    "KB_REPO_PAT":       os.environ["GITHUB_PAT"],
}

# --------------------------------------------------------------------------

def gh(method: str, path: str, body: dict | None = None):
    url  = f"{API_BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read()) if r.status not in (201, 204) or r.length else {}


def encrypt_secret(public_key_b64: str, secret_value: str) -> str:
    pk    = public.PublicKey(public_key_b64.encode(), encoding.Base64Encoder())
    box   = public.SealedBox(pk)
    enc   = box.encrypt(secret_value.encode())
    return base64.b64encode(enc).decode()


def main():
    # Fetch repo public key for secret encryption
    key_info = gh("GET", f"/repos/{REPO}/actions/secrets/public-key")
    pub_key     = key_info["key"]
    pub_key_id  = key_info["key_id"]
    print(f"Repo public key id: {pub_key_id}")

    for name, value in SECRETS.items():
        if not value:
            print(f"  SKIP {name} (empty)")
            continue
        encrypted = encrypt_secret(pub_key, value)
        gh("PUT", f"/repos/{REPO}/actions/secrets/{name}", {
            "encrypted_value": encrypted,
            "key_id": pub_key_id,
        })
        print(f"  SET  {name}")

    print("\nAll secrets pushed.")


if __name__ == "__main__":
    main()
