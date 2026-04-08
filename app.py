from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid
import json
import time
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
import math
import geohash2
import base64

# ─── APP SETUP ──────────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='')
CORS(app)

GEO_FENCE_RADIUS_METERS = 65
FILE_EXPIRY_SECONDS = 3600  # 1 hour default

print("[Setup] Generating RSA-2048 keys...")
public_key, private_key = rsa.newkeys(2048)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
LOGS_FILE = os.path.join(DATA_DIR, 'access_log.json')
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize access log
if not os.path.exists(LOGS_FILE):
    with open(LOGS_FILE, 'w') as f:
        json.dump([], f)

print(f"[Setup] Geo-fence: {GEO_FENCE_RADIUS_METERS}m | Expiry: {FILE_EXPIRY_SECONDS}s. Ready.")

# ─── HELPERS ────────────────────────────────────────────────────────
def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lam = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lam / 2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def log_access(file_id, lat, lon, distance, result, reason):
    """Append an access attempt to the JSON log file."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file_id": file_id,
        "lat": round(lat, 6),
        "lon": round(lon, 6),
        "distance_m": round(distance, 1) if distance >= 0 else None,
        "result": result,
        "reason": reason
    }
    try:
        with open(LOGS_FILE, 'r') as f:
            logs = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        logs = []
    logs.append(entry)
    with open(LOGS_FILE, 'w') as f:
        json.dump(logs, f, indent=2)
    print(f"[Log] {result} | {reason} | dist={entry['distance_m']}m | {file_id[:8]}...")

# ─── FRONTEND ROUTES ────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')

@app.route('/sender')
def sender_page():
    return send_from_directory(STATIC_DIR, 'sender.html')

@app.route('/receiver')
def receiver_page():
    return send_from_directory(STATIC_DIR, 'receiver.html')

@app.route('/logs')
def logs_page():
    return send_from_directory(STATIC_DIR, 'logs.html')

# ─── API: ENCRYPT ───────────────────────────────────────────────────
@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files.get('file')
    lat_str = request.form.get('lat')
    lon_str = request.form.get('lon')
    expiry_str = request.form.get('expiry', str(FILE_EXPIRY_SECONDS))

    if not file or not lat_str or not lon_str:
        return jsonify({"error": "Missing file or GPS coordinates"}), 400

    lat, lon = float(lat_str), float(lon_str)
    expiry_secs = int(expiry_str)
    file_data = file.read()
    file_id = str(uuid.uuid4())
    created_at = time.time()

    aes_key = get_random_bytes(32)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    enc_key = rsa.encrypt(aes_key, public_key)

    with open(os.path.join(DATA_DIR, f"{file_id}.enc"), 'wb') as f:
        f.write(cipher.nonce); f.write(tag); f.write(ciphertext)
    with open(os.path.join(DATA_DIR, f"{file_id}_key.enc"), 'wb') as f:
        f.write(enc_key)

    ghash = geohash2.encode(lat, lon, precision=7)
    meta = {
        "lat": lat, "lon": lon, "geohash": ghash,
        "filename": file.filename,
        "created_at": created_at,
        "expiry_seconds": expiry_secs,
        "file_size": len(file_data)
    }
    with open(os.path.join(DATA_DIR, f"{file_id}_meta.json"), 'w') as f:
        json.dump(meta, f)

    expires_at = datetime.fromtimestamp(created_at + expiry_secs, tz=timezone.utc).isoformat()
    print(f"[Encrypt] Locked @ ({lat:.6f}, {lon:.6f}) ID={file_id} expires={expires_at}")
    return jsonify({
        "success": True, "file_id": file_id, "geohash": ghash,
        "lat": lat, "lon": lon, "expires_at": expires_at,
        "expiry_minutes": expiry_secs // 60
    })

# ─── API: FILE INFO (check status before decrypt) ──────────────────
@app.route('/file-info', methods=['POST'])
def file_info():
    data = request.json
    file_id = data.get('file_id')
    if not file_id:
        return jsonify({"error": "Missing file_id"}), 400

    meta_path = os.path.join(DATA_DIR, f"{file_id}_meta.json")
    if not os.path.exists(meta_path):
        return jsonify({"found": False, "error": "File ID not found"}), 404

    with open(meta_path, 'r') as f:
        meta = json.load(f)

    elapsed = time.time() - meta['created_at']
    remaining = max(0, meta['expiry_seconds'] - elapsed)
    expired = remaining <= 0

    return jsonify({
        "found": True,
        "filename": meta['filename'],
        "file_size": meta.get('file_size', 0),
        "geohash": meta['geohash'],
        "expired": expired,
        "remaining_seconds": int(remaining),
        "expiry_minutes": meta['expiry_seconds'] // 60
    })

# ─── API: DECRYPT ───────────────────────────────────────────────────
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    file_id = data.get('file_id')
    lat, lon = data.get('lat'), data.get('lon')

    if not file_id or lat is None or lon is None:
        return jsonify({"error": "Missing file_id or GPS coordinates"}), 400

    meta_path = os.path.join(DATA_DIR, f"{file_id}_meta.json")
    if not os.path.exists(meta_path):
        log_access(file_id, lat, lon, -1, "DENIED", "File ID not found")
        return jsonify({"error": "Invalid File ID. Not found."}), 404

    with open(meta_path, 'r') as f:
        meta = json.load(f)

    # ── Expiry Check ──
    elapsed = time.time() - meta['created_at']
    if elapsed > meta['expiry_seconds']:
        log_access(file_id, lat, lon, -1, "DENIED", "File expired")
        return jsonify({
            "success": False,
            "message": f"File has expired. It was valid for {meta['expiry_seconds'] // 60} minutes.",
            "distance": -1, "expired": True
        })

    # ── Distance Check ──
    distance = haversine(meta['lat'], meta['lon'], lat, lon)
    recv_ghash = geohash2.encode(lat, lon, precision=7)

    if distance > GEO_FENCE_RADIUS_METERS:
        log_access(file_id, lat, lon, distance, "DENIED", "Outside geo-fence")
        return jsonify({
            "success": False,
            "message": f"Outside geo-fence. You are {distance:.1f}m away (limit: {GEO_FENCE_RADIUS_METERS}m).",
            "distance": round(distance, 1),
            "radius": GEO_FENCE_RADIUS_METERS,
            "geohash": recv_ghash
        })

    # ── Crypto Unlock ──
    try:
        with open(os.path.join(DATA_DIR, f"{file_id}_key.enc"), 'rb') as f:
            enc_key = f.read()
        aes_key = rsa.decrypt(enc_key, private_key)

        with open(os.path.join(DATA_DIR, f"{file_id}.enc"), 'rb') as f:
            nonce = f.read(16); tag = f.read(16); ciphertext = f.read()
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        log_access(file_id, lat, lon, distance, "DENIED", "Crypto failure")
        return jsonify({"success": False, "message": "Cryptographic failure", "distance": round(distance, 1)})

    remaining = max(0, meta['expiry_seconds'] - elapsed)
    log_access(file_id, lat, lon, distance, "GRANTED", "Decryption successful")

    return jsonify({
        "success": True,
        "message": f"Within authorized zone ({distance:.1f}m). Decryption granted.",
        "distance": round(distance, 1),
        "radius": GEO_FENCE_RADIUS_METERS,
        "geohash": recv_ghash,
        "filename": meta['filename'],
        "file_data": base64.b64encode(plain).decode(),
        "remaining_seconds": int(remaining)
    })

# ─── API: ACCESS LOGS ──────────────────────────────────────────────
@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        with open(LOGS_FILE, 'r') as f:
            logs = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        logs = []
    # Return most recent first
    return jsonify({"logs": list(reversed(logs))})

@app.route('/health')
def health():
    return jsonify({"status": "ok", "radius": GEO_FENCE_RADIUS_METERS, "expiry_s": FILE_EXPIRY_SECONDS})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
