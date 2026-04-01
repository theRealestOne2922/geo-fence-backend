from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import uuid
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
import math
import geohash2
import base64

app = Flask(__name__)
CORS(app)

# ─── CONFIG ─────────────────────────────────────────────────────────
GEO_FENCE_RADIUS_METERS = 65  # Geo-fence boundary in meters

# RSA Keys (generated once per server boot)
print("[Setup] Generating RSA-2048 keys...")
public_key, private_key = rsa.newkeys(2048)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
print(f"[Setup] Geo-fence radius: {GEO_FENCE_RADIUS_METERS}m")
print("[Setup] Ready.")

# ─── HAVERSINE ──────────────────────────────────────────────────────
def haversine(lat1, lon1, lat2, lon2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lam = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lam / 2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

# ─── ENCRYPT ────────────────────────────────────────────────────────
@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files.get('file')
    lat_str = request.form.get('lat')
    lon_str = request.form.get('lon')

    if not file or not lat_str or not lon_str:
        return jsonify({"error": "Missing file or GPS coordinates"}), 400

    lat, lon = float(lat_str), float(lon_str)
    file_data = file.read()
    file_id = str(uuid.uuid4())

    # AES-256 GCM encryption
    aes_key = get_random_bytes(32)
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    # RSA protect the AES key
    enc_key = rsa.encrypt(aes_key, public_key)

    # Save encrypted payload
    with open(os.path.join(DATA_DIR, f"{file_id}.enc"), 'wb') as f:
        f.write(cipher.nonce); f.write(tag); f.write(ciphertext)
    with open(os.path.join(DATA_DIR, f"{file_id}_key.enc"), 'wb') as f:
        f.write(enc_key)

    ghash = geohash2.encode(lat, lon, precision=7)
    with open(os.path.join(DATA_DIR, f"{file_id}_meta.json"), 'w') as f:
        json.dump({"lat": lat, "lon": lon, "geohash": ghash, "filename": file.filename}, f)

    print(f"[Encrypt] File locked @ ({lat:.6f}, {lon:.6f}) GeoHash={ghash} ID={file_id}")
    return jsonify({"success": True, "file_id": file_id, "geohash": ghash, "lat": lat, "lon": lon})

# ─── DECRYPT ────────────────────────────────────────────────────────
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    file_id = data.get('file_id')
    lat, lon = data.get('lat'), data.get('lon')

    if not file_id or lat is None or lon is None:
        return jsonify({"error": "Missing file_id or GPS coordinates"}), 400

    meta_path = os.path.join(DATA_DIR, f"{file_id}_meta.json")
    if not os.path.exists(meta_path):
        return jsonify({"error": "Invalid File ID. Not found."}), 404

    with open(meta_path, 'r') as f:
        meta = json.load(f)

    distance = haversine(meta['lat'], meta['lon'], lat, lon)
    recv_ghash = geohash2.encode(lat, lon, precision=7)

    print(f"[Decrypt] Attempt from ({lat:.6f}, {lon:.6f}) dist={distance:.1f}m limit={GEO_FENCE_RADIUS_METERS}m")

    if distance > GEO_FENCE_RADIUS_METERS:
        return jsonify({
            "success": False,
            "message": f"Outside geo-fence. You are {distance:.1f}m away (limit: {GEO_FENCE_RADIUS_METERS}m).",
            "distance": round(distance, 1),
            "radius": GEO_FENCE_RADIUS_METERS,
            "geohash": recv_ghash
        })

    # Within range — decrypt
    try:
        with open(os.path.join(DATA_DIR, f"{file_id}_key.enc"), 'rb') as f:
            enc_key = f.read()
        aes_key = rsa.decrypt(enc_key, private_key)

        with open(os.path.join(DATA_DIR, f"{file_id}.enc"), 'rb') as f:
            nonce = f.read(16); tag = f.read(16); ciphertext = f.read()
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plain = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        return jsonify({"success": False, "message": "Cryptographic failure", "distance": round(distance, 1)})

    return jsonify({
        "success": True,
        "message": f"Within authorized zone ({distance:.1f}m). Decryption granted.",
        "distance": round(distance, 1),
        "radius": GEO_FENCE_RADIUS_METERS,
        "geohash": recv_ghash,
        "filename": meta['filename'],
        "file_data": base64.b64encode(plain).decode()
    })

# ─── HEALTH ─────────────────────────────────────────────────────────
@app.route('/health')
def health():
    return jsonify({"status": "ok", "radius": GEO_FENCE_RADIUS_METERS})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
