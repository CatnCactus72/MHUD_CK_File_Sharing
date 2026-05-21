import os
import psycopg2
import datetime
import requests
import jwt
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import time 

app = Flask(__name__)

# Cấu hình đường dẫn phẳng (Flat) trực tiếp tại gốc theo đúng Đặc tả mục 10
DB_PATH = "./nonce_store.db"
AUTH_PRIV_KEY_PATH = "./auth_priv_key.pem"
AUTH_PUB_KEY_PATH = "./auth_pub_key.pem"

CA_SERVER_URL = "http://ca_server:5001"
NONCE_TTL_MINUTES = 5

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "secure_file_sharing"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASS", "123456")
    )

def init_system():
    """Khởi tạo database nonce_store.db và cặp khóa RSA trực tiếp tại thư mục gốc."""
    # Khởi tạo Database (Bao gồm bảng Users và bảng dữ liệu Nonce Store bền vững)
    
    # tránh xung đột với file_server khi tạo container Docker
    # nếu vẫn lỗi, chạy lệnh sau 
    # docker-compose restart auth_server
    # sau đó gõ lệnh docker-compose ps, nếu xuất hiện 4 dòng đều có trạng thái Up là ok
    time.sleep(5) 
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            cert_pem TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp TIMESTAMP NOT NULL 
        )
    ''')
    conn.commit()
    conn.close()

    # Khởi tạo cặp khóa RSA phục vụ ký nhận Session Ticket
    if not os.path.exists(AUTH_PRIV_KEY_PATH) or os.path.getsize(AUTH_PRIV_KEY_PATH) == 0:
        print("[AUTH SERVER] Đang tiến hành tạo cặp khóa RSA ký Session Ticket tại thư mục gốc...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(AUTH_PRIV_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(AUTH_PUB_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def cleanup_old_nonces():
    """Tự động dọn dẹp các nonce đã vượt quá thời gian TTL quy định"""
    conn = get_db_connection()
    cursor = conn.cursor()
    expiration_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=NONCE_TTL_MINUTES)
    cursor.execute("DELETE FROM nonces WHERE timestamp < %s", (expiration_time,))
    conn.commit()
    conn.close()

def check_replay_attack(nonce, timestamp_str):
    """Xác thực thực thể bảo vệ chống tấn công phát lại (Replay Attack)"""
    try:
        req_time = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return False, "400 Invalid timestamp format."

    now = datetime.datetime.utcnow()
    
    # 1. Kiểm tra độ lệch cửa sổ thời gian (Window TTL)
    if abs((now - req_time).total_seconds()) > NONCE_TTL_MINUTES * 60:
        return False, "403 Request timestamp out of window."

    cleanup_old_nonces()

    # 2. Thực hiện tra cứu kiểm tra trùng lặp Nonce trong kho lưu trữ bền vững
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT nonce FROM nonces WHERE nonce = %s", (nonce,))
    if cursor.fetchone() is not None:
        conn.close()
        return False, "403 Replay Attack Detected: Nonce already used!"
    
    # Lưu vết Nonce hợp lệ mới vào hệ thống
    cursor.execute("INSERT INTO nonces (nonce, timestamp) VALUES (%s, %s)", (nonce, req_time))
    conn.commit()
    conn.close()
    return True, "OK"

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username, password, csr = data.get('username'), data.get('password'), data.get('csr')

    if not all([username, password, csr]):
        return jsonify({"error": "Thiếu dữ liệu đầu vào"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Username đã tồn tại"}), 409

    try:
        ca_resp = requests.post(f"{CA_SERVER_URL}/issue_cert", json={"csr": csr})
        if ca_resp.status_code != 200:
            return jsonify({"error": "CA Server từ chối cấp chứng chỉ"}), 500
        cert_chain = ca_resp.json().get('cert_chain')
    except Exception as e:
        return jsonify({"error": f"Lỗi kết nối CA Server: {str(e)}"}), 500

    password_hash = generate_password_hash(password)
    cursor.execute("INSERT INTO users (username, password_hash, cert_pem) VALUES (%s, %s, %s)", 
                   (username, password_hash, cert_chain))
    conn.commit()
    conn.close()

    return jsonify({"message": "Đăng ký thành công", "cert_chain": cert_chain}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username, password = data.get('username'), data.get('password')
    nonce, timestamp = data.get('nonce'), data.get('timestamp')

    if not all([username, password, nonce, timestamp]):
        return jsonify({"error": "Thiếu dữ liệu đầu vào"}), 400

    is_valid, msg = check_replay_attack(nonce, timestamp)
    if not is_valid:
        return jsonify({"error": msg}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, cert_pem FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not check_password_hash(row[0], password):
        return jsonify({"error": "Sai tài khoản hoặc mật khẩu"}), 401

    user_cert_pem = row[1]

    try:
        crl_resp = requests.get(f"{CA_SERVER_URL}/crl")
        if crl_resp.status_code == 200:
            crl = x509.load_pem_x509_crl(crl_resp.content)
            user_cert = x509.load_pem_x509_certificate(user_cert_pem.encode('utf-8'))
            for revoked in crl:
                if revoked.serial_number == user_cert.serial_number:
                    return jsonify({"error": "Certificate revoked. Access denied."}), 403
    except Exception as e:
        return jsonify({"error": "Không thể xác minh trạng thái thu hồi chứng chỉ (CRL)."}), 500

    with open(AUTH_PRIV_KEY_PATH, "rb") as f:
        auth_priv_key = serialization.load_pem_private_key(f.read(), password=None)

    issued_at = datetime.datetime.utcnow()
    expires_at = issued_at + datetime.timedelta(hours=2)

    payload = {"username": username, "iat": issued_at, "exp": expires_at}
    session_ticket = jwt.encode(payload, auth_priv_key, algorithm="RS256")

    print(f"[AUTH] User '{username}' logged in successfully. Ticket issued.")
    return jsonify({"session_ticket": session_ticket}), 200

@app.route('/public_key', methods=['GET'])
def get_public_key():
    try:
        with open(AUTH_PUB_KEY_PATH, "r") as f:
            pub_key = f.read()
        return jsonify({"auth_public_key": pub_key}), 200
    except Exception as e:
        return jsonify({"error": "Chưa tạo public key"}), 500


@app.route('/registry/<username>', methods=['GET'])
def get_user_cert(username):
    """Public Key Registry: Trả về X.509 Certificate của user từ database của Auth Server"""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Truy vấn trực tiếp từ bảng users
    cursor.execute("SELECT cert_pem FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return jsonify({"cert_pem": row[0]}), 200
    return jsonify({"error": "Không tìm thấy chứng chỉ người dùng"}), 404

if __name__ == '__main__':
    init_system()
    app.run(host='0.0.0.0', port=5002)