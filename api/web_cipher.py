#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Serverless Flask app for Vercel — password-gated PSK encrypt/decrypt (scrypt + AES-256-GCM)
# Single-file handler (WSGI). All routes handled in this file.
#
# ENV VARS (set in Vercel project settings):
#   ADMIN_PASSWORD     -> required; the site login password you choose
#   FLASK_SECRET_KEY   -> optional; random string; if unset we auto-generate at cold start
#   SCRYPT_N           -> optional; default 16384 (2**14). You can set 8192 or 32768 etc.
#   SCRYPT_R           -> optional; default 8
#   SCRYPT_P           -> optional; default 1
#
# Local dev (optional):
#   pip install -r requirements.txt
#   $env:ADMIN_PASSWORD="your-strong-password"
#   python api/web_cipher.py

import os
import io
import secrets
import base64
from typing import Optional, Tuple

from flask import Flask, request, redirect, url_for, render_template_string, session, send_file
from werkzeug.middleware.proxy_fix import ProxyFix

# -------------------- Configuration --------------------

DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")  # must be set on Vercel
if not DEFAULT_ADMIN_PASSWORD:
    # For local accidental runs without env var: set a random throwaway to avoid empty auth.
    DEFAULT_ADMIN_PASSWORD = secrets.token_urlsafe(16)

ADMIN_PASSWORD = DEFAULT_ADMIN_PASSWORD

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default

SCRYPT_N = _int_env("SCRYPT_N", 2 ** 14)  # ≈64 MiB working memory
SCRYPT_R = _int_env("SCRYPT_R", 8)
SCRYPT_P = _int_env("SCRYPT_P", 1)
DKLEN = 32

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_urlsafe(32)

# -------------------- Dependencies --------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    raise SystemExit("Missing dependency: cryptography") from e

import hashlib

# -------------------- Crypto Helpers --------------------

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64u_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def scrypt_kdf(passphrase: str, salt: bytes, dklen: int = DKLEN,
               n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    """
    scrypt — memory-hard KDF to slow down brute-force.

    Some OpenSSL builds enforce a low default memory ceiling. Compute an explicit
    maxmem with headroom to prevent "digital envelope routines" memory limit errors.
    """
    m_cost = 128 * r * n
    overhead = 128 * r * p
    maxmem = max(64 * 1024 * 1024, m_cost + overhead + (8 * 1024 * 1024))
    try:
        return hashlib.scrypt(passphrase.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=maxmem)
    except TypeError:
        # Older Pythons without maxmem param
        return hashlib.scrypt(passphrase.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)  # 96-bit nonce
    ct = AESGCM(key).encrypt(nonce, plaintext, aad if aad else None)
    return nonce, ct

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad if aad else None)

def psk_encrypt(passphrase: str, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    salt = os.urandom(16)
    key = scrypt_kdf(passphrase, salt, DKLEN)
    nonce, ct = aesgcm_encrypt(key, plaintext, aad)
    env = (
        b'{' +
        b'"v":1,' +
        b'"t":"psk",' +
        b'"salt":"' + b64u_encode(salt).encode('ascii') + b'",' +
        b'"nonce":"' + b64u_encode(nonce).encode('ascii') + b'",' +
        b'"ct":"' + b64u_encode(ct).encode('ascii') + b'"' +
        (b',"aad":"' + b64u_encode(aad).encode('ascii') + b'"' if aad else b'') +
        b'}'
    )
    return env

def psk_decrypt(passphrase: str, envelope_bytes: bytes, aad_override: Optional[bytes] = None) -> bytes:
    s = envelope_bytes.decode('utf-8', errors='strict').strip()

    def get_field(name: str) -> Optional[str]:
        key = f'"{name}":"'
        i = s.find(key)
        if i == -1:
            return None
        j = s.find('"', i + len(key))
        if j == -1:
            return None
        return s[i + len(key):j]

    if get_field("t") != "psk":
        raise ValueError("Envelope is not PSK type")

    salt_b64 = get_field("salt")
    nonce_b64 = get_field("nonce")
    ct_b64 = get_field("ct")
    aad_b64 = get_field("aad")

    if not (salt_b64 and nonce_b64 and ct_b64):
        raise ValueError("Envelope missing required fields")

    salt = b64u_decode(salt_b64)
    nonce = b64u_decode(nonce_b64)
    ct = b64u_decode(ct_b64)
    aad = aad_override if aad_override is not None else (b64u_decode(aad_b64) if aad_b64 else None)

    key = scrypt_kdf(passphrase, salt, DKLEN)
    return aesgcm_decrypt(key, nonce, ct, aad)

# -------------------- Web App --------------------

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

def is_authed() -> bool:
    return session.get("auth", False) is True

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = request.form.get("password", "")
        if not ADMIN_PASSWORD:
            return render_template_string(LOGIN_HTML, error="Admin password is not set.")
        if secrets.compare_digest(pw, ADMIN_PASSWORD):
            session["auth"] = True
            return redirect(url_for("home"))
        return render_template_string(LOGIN_HTML, error="Incorrect password.")
    return render_template_string(LOGIN_HTML, error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/", methods=["GET"])
def home():
    if not is_authed():
        return redirect(url_for("login"))
    return render_template_string(HOME_HTML)

@app.route("/encrypt", methods=["POST"])
def route_encrypt():
    if not is_authed():
        return redirect(url_for("login"))

    passphrase = request.form.get("passphrase", "")
    aad_text = request.form.get("aad", "")
    mode = request.form.get("inmode", "text")

    if not passphrase:
        return render_template_string(HOME_HTML, enc_error="Passphrase is required.", dec_error=None)

    if mode == "text":
        plaintext = request.form.get("plaintext", "")
        pt_bytes = plaintext.encode("utf-8")
        in_name = "message.txt"
    else:
        up = request.files.get("infile")
        if not up or up.filename == "":
            return render_template_string(HOME_HTML, enc_error="No file uploaded.", dec_error=None)
        pt_bytes = up.read()
        in_name = up.filename

    aad = aad_text.encode("utf-8") if aad_text else None

    try:
        env = psk_encrypt(passphrase, pt_bytes, aad=aad)
    except Exception as e:
        return render_template_string(HOME_HTML, enc_error=f"Encrypt error: {e}", dec_error=None)

    out_name = os.path.splitext(in_name)[0] + ".enc"
    return send_file(
        io.BytesIO(env),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=out_name
    )

@app.route("/decrypt", methods=["POST"])
def route_decrypt():
    if not is_authed():
        return redirect(url_for("login"))

    passphrase = request.form.get("passphrase_dec", "")
    aad_text = request.form.get("aad_dec", "")
    up = request.files.get("encfile")

    if not passphrase:
        return render_template_string(HOME_HTML, enc_error=None, dec_error="Passphrase is required.")
    if not up or up.filename == "":
        return render_template_string(HOME_HTML, enc_error=None, dec_error="No .enc file uploaded.")

    env = up.read()
    aad = aad_text.encode("utf-8") if aad_text else None

    try:
        pt = psk_decrypt(passphrase, env, aad_override=aad)
    except Exception as e:
        return render_template_string(HOME_HTML, enc_error=None, dec_error=f"Decrypt error: {e}")

    try:
        preview = pt.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        is_text = False

    if is_text:
        return render_template_string(HOME_HTML, dec_ok_text=preview)
    else:
        base = os.path.splitext(up.filename)[0]
        out_name = f"{base}.dec.bin"
        return send_file(
            io.BytesIO(pt),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=out_name
        )

# -------------------- HTML (inline templates) --------------------

LOGIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Locked — Web Cipher</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;margin:0;background:#0f1115;color:#e8eaf0}
.wrapper{max-width:560px;margin:6rem auto;padding:2rem;background:#171a21;border:1px solid #2a2f3a;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,0.35)}
h1{margin:0 0 1rem;font-weight:700;font-size:1.4rem}
label{display:block;margin:.75rem 0 .3rem;color:#c5c9d3}
input[type=password]{width:100%;padding:.75rem;border-radius:8px;border:1px solid #2a2f3a;background:#0f1218;color:#e8eaf0}
button{margin-top:1rem;padding:.7rem 1rem;border:0;border-radius:8px;background:#3a82f7;color:white;font-weight:600;cursor:pointer}
.error{margin-top:.75rem;color:#ff6b6b}
.small{opacity:.7;font-size:.9rem;margin-top:1rem}
</style>
</head>
<body>
  <div class="wrapper">
    <h1>Enter Site Password</h1>
    <form method="post" autocomplete="off">
      <label for="pw">Password</label>
      <input id="pw" type="password" name="password" required autofocus>
      <button type="submit">Unlock</button>
      {% if error %}<div class="error">{{error}}</div>{% endif %}
      <div class="small">Set <code>ADMIN_PASSWORD</code> in Vercel → Settings → Environment Variables.</div>
    </form>
  </div>
</body>
</html>
"""

HOME_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Web Cipher — PSK AES-256-GCM</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{
  --bg:#0f1115;--panel:#171a21;--muted:#c5c9d3;--text:#e8eaf0;--accent:#3a82f7;--border:#2a2f3a;--ok:#22c55e;--err:#ef4444;
}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;margin:0;background:var(--bg);color:var(--text)}
.container{max-width:1000px;margin:2rem auto;padding:0 1rem}
.header{display:flex;gap:1rem;align-items:center;justify-content:space-between}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem 1.25rem;margin:1rem 0}
h1{font-size:1.4rem;margin:0 0 .25rem} h2{font-size:1.1rem;margin:.2rem 0 .8rem;color:var(--muted)}
label{display:block;margin:.65rem 0 .25rem;color:var(--muted)}
input[type=text],input[type=password],textarea{width:100%;padding:.75rem;border-radius:8px;border:1px solid var(--border);background:#0f1218;color:var(--text)}
textarea{min-height:120px;resize:vertical}
.row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
button{padding:.7rem 1rem;border:0;border-radius:8px;background:var(--accent);color:white;font-weight:600;cursor:pointer}
.small{font-size:.9rem;color:var(--muted)}
hr{border:0;border-top:1px solid var(--border);margin:1rem 0}
.badge{display:inline-block;padding:.2rem .5rem;border-radius:6px;background:#0f1218;border:1px solid var(--border);color:var(--muted);font-size:.8rem}
.msg-ok{color:var(--ok)} .msg-err{color:var(--err)}
nav a{color:var(--muted);text-decoration:none} nav a:hover{color:#fff}
.toggle{display:flex;gap:.5rem;align-items:center;margin:.5rem 0}
</style>
<script>
function swapInputMode() {
  const mode = document.querySelector('input[name=\"inmode\"]:checked').value;
  document.getElementById('textMode').style.display = (mode === 'text') ? 'block' : 'none';
  document.getElementById('fileMode').style.display = (mode === 'file') ? 'block' : 'none';
}
window.addEventListener('DOMContentLoaded', swapInputMode);
</script>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Web Cipher</h1>
      <div class="small">Pre-shared passphrase → scrypt → AES-256-GCM</div>
    </div>
    <nav><a href="{{url_for('logout')}}">Logout</a></nav>
  </div>

  <div class="card">
    <span class="badge">Encrypt</span>
    <form method="post" action="{{url_for('route_encrypt')}}" enctype="multipart/form-data">
      <div class="row">
        <div>
          <label>Passphrase</label>
          <input type="password" name="passphrase" required>
        </div>
        <div>
          <label>Optional AAD (bind context)</label>
          <input type="text" name="aad" placeholder="e.g., filename or purpose tag">
        </div>
      </div>

      <div class="toggle">
        <label><input type="radio" name="inmode" value="text" checked onchange="swapInputMode()"> Enter text</label>
        <label><input type="radio" name="inmode" value="file" onchange="swapInputMode()"> Upload file</label>
      </div>

      <div id="textMode">
        <label>Plaintext</label>
        <textarea name="plaintext" placeholder="Type or paste your message here"></textarea>
      </div>

      <div id="fileMode" style="display:none">
        <label>Input file</label>
        <input type="file" name="infile" accept="*/*">
      </div>

      <div style="margin-top:.75rem">
        <button type="submit">Encrypt → Download .enc</button>
      </div>

      {% if enc_error %}<div class="msg-err" style="margin-top:.75rem">{{enc_error}}</div>{% endif %}
    </form>
  </div>

  <div class="card">
    <span class="badge">Decrypt</span>
    <form method="post" action="{{url_for('route_decrypt')}}" enctype="multipart/form-data">
      <div class="row">
        <div>
          <label>Passphrase</label>
          <input type="password" name="passphrase_dec" required>
        </div>
        <div>
          <label>Optional AAD (must match if set on encrypt)</label>
          <input type="text" name="aad_dec" placeholder="Same AAD used at encrypt (if any)">
        </div>
      </div>

      <label>.enc file</label>
      <input type="file" name="encfile" accept=".enc,application/octet-stream">

      <div style="margin-top:.75rem">
        <button type="submit">Decrypt</button>
      </div>

      {% if dec_error %}<div class="msg-err" style="margin-top:.75rem">{{dec_error}}</div>{% endif %}
      {% if dec_ok_text %}
      <hr>
      <div class="small">Decrypted text preview:</div>
      <textarea readonly>{{dec_ok_text}}</textarea>
      {% endif %}
    </form>
  </div>

  <div class="card">
    <h2>Notes</h2>
    <div class="small">
      scrypt parameters: N={{N}}, r={{R}}, p={{P}}. Configure via Vercel env vars <code>SCRYPT_N</code>, <code>SCRYPT_R</code>, <code>SCRYPT_P</code>.
    </div>
  </div>
</div>
</body>
</html>
""".replace("{{N}}", str(SCRYPT_N)).replace("{{R}}", str(SCRYPT_R)).replace("{{P}}", str(SCRYPT_P))

# -------------- Local dev entrypoint --------------

if __name__ == "__main__":
    os.environ.setdefault("FLASK_RUN_FROM_CLI", "true")
    print("Running local dev server at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
