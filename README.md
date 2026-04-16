# Geo-Fenced Secure File Transfer

This is a full-stack geo-fenced secure file transfer application with advanced security features including time-based access control, one-time decryption (burn-after-reading), comprehensive access logging, automated SMS OTP delivery, and an automated alert system for unauthorized access attempts.

## Live Demo
**Working Link:** [https://geo-fence-backend-hx1g.onrender.com](https://geo-fence-backend-hx1g.onrender.com)

## Advanced Security Features Enabled

1. **Device Binding**
   - Captures the receiver's browser `User-Agent` string at the time of file upload.
   - During decryption, the server compares the incoming device signature against the stored one.

2. **One-Time Decryption (Burn After Reading)**
   - Sender can mark a file as single-use before encrypting.
   - After the first successful decryption, a `decrypted: true` flag is written to the file metadata.
   - All subsequent decryption attempts are permanently blocked regardless of location or credentials.

3. **Time-Based Access Control (File Expiry)**
   - Sender selects a time window during encryption: 30 min / 1 hour / 2 hours / 24 hours.
   - Server checks `created_at + expiry_seconds` against current time on every access attempt.
   - Expired files cannot be decrypted even from the correct location and device.

4. **Two-Factor OTP Verification**
   - A 6-digit OTP is generated server-side only after all primary checks pass (device, expiry, geo-fence).
   - Free fallback SMS delivery via **Textbelt** integrated.
   - OTP has a 5-minute validity window.
   - Decryption only proceeds if the correct OTP is submitted — adds a second factor beyond physical location.

5. **Multi-Gate Sequential Security Model**
   - 5 independent security gates enforced in order: Device Signature Match ➔ OTP Validity ➔ One-Time Check ➔ Time Expiry ➔ Geo-Fence Distance Check (Haversine, ≤65m limit).
   - All 5 must pass before the RSA container unlocks the AES-256 key.

6. **Monitoring and Auditing**
   - Extensive Access Logging system mapping distance, GPS, time, and boolean pass/fail status.
   - Separate Alert system logging unauthorized access attempts with severity indicators (`CRITICAL` for geo-fence violations, `WARNING` for others).
   - Real-time dashboard at `/logs` displaying all alerts.

## Running Locally

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the server:
   ```bash
   python app.py
   ```
3. Visit `http://localhost:5001`.
