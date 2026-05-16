import os
import sqlite3
import datetime
import jwt
import requests
from functools import wraps
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Cấu hình thư mục
DB_PATH = "./database/file_server.db"
STORAGE_DIR = "./storage"
LOG_PATH = "./logs/audit_log.txt"

# URL của Auth Server (để lấy Public Key xác thực JWT)
AUTH_SERVER_URL = "http://auth_server:5002"
NONCE_TTL_MINUTES = 5

AUTH_PUBLIC_KEY = None

def init_system():
    """Khởi tạo database, thư mục lưu trữ và file log"""
    os.makedirs("./database", exist_ok=True)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    os.makedirs("./logs", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Bảng lưu Nonce chống Replay Attack
    cursor.execute('''CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, timestamp DATETIME NOT NULL)''')
    # Bảng Public Key Registry (lưu chứng chỉ của user)
    cursor.execute('''CREATE TABLE IF NOT EXISTS public_keys (username TEXT PRIMARY KEY, cert_pem TEXT NOT NULL)''')
    # Bảng siêu dữ liệu tệp tin
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            filename TEXT,
            owner TEXT,
            target_group TEXT, -- Tên người nhận (nếu gửi cá nhân)
            group_name TEXT,   -- Tên nhóm (nếu gửi nhóm, ngược lại để NULL)
            wrapped_fsk TEXT,  -- Khóa FSK đã mã hóa bọc
            upload_time DATETIME
        )
    ''')
    # Bảng metadata nhóm
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_name TEXT PRIMARY KEY,
            admin TEXT,
            created_at DATETIME
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_name TEXT,
            username TEXT,
            display_name TEXT,
            wrapped_gmk TEXT,
            status TEXT, -- 'active' hoặc 'pending'
            PRIMARY KEY (group_name, username)
        )
    ''')
    conn.commit()
    conn.close()

    # Tạo file log nếu chưa có
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w") as f:
            f.write("=== SECURE FILE SHARING AUDIT LOG ===\n")

def write_audit_log(category, message):
    """Ghi log kiểm toán theo định dạng đặc tả"""
    timestamp = datetime.datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] [{category}] {message}\n"
    with open(LOG_PATH, "a") as f:
        f.write(log_entry)
    print(log_entry.strip())

def get_auth_public_key():
    """Lấy Public Key của Auth Server để xác thực JWT Session Ticket"""
    global AUTH_PUBLIC_KEY
    if AUTH_PUBLIC_KEY is None:
        try:
            resp = requests.get(f"{AUTH_SERVER_URL}/public_key")
            if resp.status_code == 200:
                AUTH_PUBLIC_KEY = resp.json().get("auth_public_key")
        except Exception as e:
            print(f"[FILE SERVER] Lỗi lấy Auth Public Key: {str(e)}")
    return AUTH_PUBLIC_KEY

def cleanup_old_nonces():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    expiration_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=NONCE_TTL_MINUTES)
    cursor.execute("DELETE FROM nonces WHERE timestamp < ?", (expiration_time,))
    conn.commit()
    conn.close()

def require_auth(f):
    """
    Decorator Middleware: Xác thực Session Ticket (JWT) và Nonce (Replay Attack)
    cho MỌI request gửi đến File Server.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Lấy dữ liệu header
        token = request.headers.get('Authorization')
        nonce = request.headers.get('X-Nonce')
        timestamp_str = request.headers.get('X-Timestamp')

        if not all([token, nonce, timestamp_str]):
            return jsonify({"error": "Thiếu thông tin xác thực, Nonce hoặc Timestamp"}), 400

        token = token.replace("Bearer ", "")

        # 2. Kiểm tra Replay Attack (Nonce + Timestamp)
        try:
            req_time = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return jsonify({"error": "400 Invalid timestamp format."}), 400

        now = datetime.datetime.utcnow()
        if abs((now - req_time).total_seconds()) > NONCE_TTL_MINUTES * 60:
            return jsonify({"error": "403 Request timestamp out of window."}), 403

        cleanup_old_nonces()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT nonce FROM nonces WHERE nonce = ?", (nonce,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "403 Replay Attack Detected: Nonce already used!"}), 403
        
        cursor.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (nonce, req_time))
        conn.commit()
        conn.close()

        # 3. Xác minh Session Ticket (JWT signature)
        pub_key = get_auth_public_key()
        if not pub_key:
            return jsonify({"error": "Internal Server Error: Missing Auth Key"}), 500

        try:
            payload = jwt.decode(token, pub_key, algorithms=["RS256"])
            request.user = payload['username'] # Gắn username vào request object
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session Ticket đã hết hạn"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Session Ticket không hợp lệ"}), 401

        return f(*args, **kwargs)
    return decorated

# ==========================================
# CÁC ENDPOINT CHÍNH (Được bảo vệ bởi require_auth)
# ==========================================

@app.route('/upload', methods=['POST'])
@require_auth
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "Không có dữ liệu tệp"}), 400
        
    file = request.files['file']
    filename = secure_filename(request.form.get('filename', 'encrypted_blob.bin'))
    target_group = request.form.get('target')  # Đối với cá nhân
    group_name = request.form.get('group_name')  # Đối với nhóm (Có thể NULL)
    wrapped_fsk = request.form.get('wrapped_fsk')

    if not wrapped_fsk:
        return jsonify({"error": "Thiếu thông tin bọc khóawrapped_fsk"}), 400

    import uuid
    file_id = str(uuid.uuid4())
    save_path = os.path.join(STORAGE_DIR, file_id)
    file.save(save_path)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Thêm group_name vào bản ghi tệp tin
    cursor.execute(
        "INSERT INTO files (file_id, filename, owner, target_group, group_name, wrapped_fsk, upload_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (file_id, filename, request.user, target_group, group_name, wrapped_fsk, datetime.datetime.utcnow())
    )
    conn.commit()
    conn.close()

    log_target = group_name if group_name else target_group
    write_audit_log("FILE", f"User '{request.user}' uploaded file '{filename}' to target '{log_target}'.")
    return jsonify({"message": "Upload thành công", "file_id": file_id}), 200

@app.route('/groups/me', methods=['GET'])
@require_auth
def get_my_groups():
    """Lấy danh sách nhóm (active) và lời mời (pending)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Nhóm đang tham gia (Active)
    cursor.execute('''
        SELECT g.group_name, g.admin, g.created_at, 
               (SELECT COUNT(*) FROM group_members WHERE group_name = g.group_name AND status = 'active') as member_count
        FROM groups g
        JOIN group_members m ON g.group_name = m.group_name
        WHERE m.username = ? AND m.status = 'active'
    ''', (request.user,))
    active_groups = [{"group_name": r[0], "admin": r[1], "created_at": r[2], "member_count": r[3]} for r in cursor.fetchall()]
    
    # Lời mời chờ xử lý (Pending)
    cursor.execute('''
        SELECT g.group_name, g.admin, m.wrapped_gmk
        FROM groups g
        JOIN group_members m ON g.group_name = m.group_name
        WHERE m.username = ? AND m.status = 'pending'
    ''', (request.user,))
    invitations = [{"group_name": r[0], "admin": r[1], "wrapped_gmk": r[2]} for r in cursor.fetchall()]
    
    conn.close()
    return jsonify({"active": active_groups, "invitations": invitations}), 200

@app.route('/group/create', methods=['POST'])
@require_auth
def create_group():
    data = request.json
    group_name = data.get('group_name')
    wrapped_gmk = data.get('wrapped_gmk')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO groups (group_name, admin, created_at) VALUES (?, ?, ?)", 
                       (group_name, request.user, created_at))
        cursor.execute("INSERT INTO group_members (group_name, username, display_name, wrapped_gmk, status) VALUES (?, ?, ?, ?, 'active')", 
                       (group_name, request.user, request.user, wrapped_gmk))
        conn.commit()
        write_audit_log("GROUP", f"User '{request.user}' created group '{group_name}'.")
        return jsonify({"message": "Success"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Tên nhóm đã tồn tại."}), 409
    finally:
        conn.close()

@app.route('/group/<group_name>/members', methods=['GET'])
@require_auth
def get_group_members(group_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username, display_name FROM group_members WHERE group_name = ? AND status = 'active'", (group_name,))
    members = [{"username": r[0], "display_name": r[1] or r[0]} for r in cursor.fetchall()]
    conn.close()
    return jsonify({"members": members}), 200

@app.route('/group/<group_name>/action', methods=['POST'])
@require_auth
def group_action(group_name):
    """Endpoint xử lý đa năng cho các hành động Nhóm (Mời, Rời, Xóa, Cập nhật...)"""
    data = request.json
    action = data.get('action')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT admin FROM groups WHERE group_name = ?", (group_name,))
    group_row = cursor.fetchone()
    if not group_row:
        return jsonify({"error": "Group not found"}), 404
    
    admin = group_row[0]
    is_admin = (request.user == admin)
    
    try:
        if action == "invite":
            if not is_admin: return jsonify({"error": "Access Denied"}), 403
            target, wrapped_gmk = data.get('target_user'), data.get('wrapped_gmk')
            cursor.execute("INSERT INTO group_members (group_name, username, wrapped_gmk, status) VALUES (?, ?, ?, 'pending')", 
                           (group_name, target, wrapped_gmk))
            
        elif action == "accept_invite":
            display_name = data.get('display_name')
            cursor.execute("UPDATE group_members SET status = 'active', display_name = ? WHERE group_name = ? AND username = ?", 
                           (display_name, group_name, request.user))
                           
        elif action == "decline_invite":
            cursor.execute("DELETE FROM group_members WHERE group_name = ? AND username = ? AND status = 'pending'", (group_name, request.user))
            
        elif action == "remove":
            if not is_admin: return jsonify({"error": "Access Denied"}), 403
            cursor.execute("DELETE FROM group_members WHERE group_name = ? AND username = ?", (group_name, data.get('target_user')))
            # (Thực tế hệ thống sẽ cần kích hoạt Xoay vòng khóa ở Client sau bước này)
            
        elif action == "edit_display_name":
            cursor.execute("UPDATE group_members SET display_name = ? WHERE group_name = ? AND username = ?", 
                           (data.get('new_name'), group_name, request.user))
                           
        elif action == "edit_group_name":
            if not is_admin: return jsonify({"error": "Access Denied"}), 403
            new_name = data.get('new_name')
            cursor.execute("UPDATE groups SET group_name = ? WHERE group_name = ?", (new_name, group_name))
            cursor.execute("UPDATE group_members SET group_name = ? WHERE group_name = ?", (new_name, group_name))
            
        elif action == "transfer_admin":
            if not is_admin: return jsonify({"error": "Access Denied"}), 403
            cursor.execute("UPDATE groups SET admin = ? WHERE group_name = ?", (data.get('target_user'), group_name))
            
        elif action == "leave":
            cursor.execute("SELECT COUNT(*) FROM group_members WHERE group_name = ? AND status = 'active'", (group_name,))
            count = cursor.fetchone()[0]
            if is_admin and count > 1:
                return jsonify({"error": "You are the admin. Transfer admin rights before leaving. Use option 6."}), 400
            cursor.execute("DELETE FROM group_members WHERE group_name = ? AND username = ?", (group_name, request.user))
            if count == 1: # Xóa nhóm nếu là người cuối cùng
                cursor.execute("DELETE FROM groups WHERE group_name = ?", (group_name,))
                
        elif action == "delete":
            if not is_admin: return jsonify({"error": "Access Denied"}), 403
            cursor.execute("DELETE FROM groups WHERE group_name = ?", (group_name,))
            cursor.execute("DELETE FROM group_members WHERE group_name = ?", (group_name,))
            
        conn.commit()
        return jsonify({"message": "Action completed"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/group/<group_name>', methods=['GET'])
@require_auth
def get_group_details(group_name):
    """API phục vụ trích xuất gói khóa GMK và thông tin thành viên (Bị thiếu ở bản trước)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Lấy thông tin Admin
    cursor.execute("SELECT admin FROM groups WHERE group_name = ?", (group_name,))
    group_info = cursor.fetchone()
    if not group_info:
        conn.close()
        return jsonify({"error": "Không tìm thấy nhóm"}), 404
        
    # 2. Lấy danh sách thành viên (Active) kèm theo bản bọc khóa GMK của họ
    cursor.execute("SELECT username, wrapped_gmk FROM group_members WHERE group_name = ? AND status = 'active'", (group_name,))
    members = [{"username": r[0], "wrapped_gmk": r[1]} for r in cursor.fetchall()]
    conn.close()
    
    # 3. Kiểm tra xem người yêu cầu có đang ở trong nhóm không (Bảo mật)
    if not any(m['username'] == request.user for m in members):
        return jsonify({"error": "Từ chối truy cập. Bạn không nằm trong nhóm này."}), 403
        
    return jsonify({
        "group_name": group_name, 
        "admin": group_info[0], 
        "members": members
    }), 200

@app.route('/files/pending', methods=['GET'])
@require_auth
def get_pending_files():
    """Lấy danh sách tệp tin chờ xử lý (Hỗ trợ phân tách cá nhân và nhóm)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT file_id, filename, owner, target_group, group_name, wrapped_fsk, upload_time 
        FROM files 
        WHERE target_group = ? 
           OR (group_name IS NOT NULL AND group_name IN (SELECT group_name FROM group_members WHERE username = ? AND status = 'active'))
    ''', (request.user, request.user))
    
    rows = cursor.fetchall()
    conn.close()
    
    file_list = []
    for r in rows:
        file_list.append({
            "file_id": r[0], "filename": r[1], "owner": r[2],
            "target_group": r[3], "group_name": r[4], "wrapped_fsk": r[5], "upload_time": r[6]
        })
    return jsonify({"files": file_list}), 200

@app.route('/files/download/<file_id>', methods=['GET'])
@require_auth
def download_file_blob(file_id):
    """Tải blob nhị phân đã mã hóa của tệp tin"""
    file_path = os.path.join(STORAGE_DIR, file_id)
    if not os.path.exists(file_path):
        return jsonify({"error": "Không tìm thấy tệp tin trên máy chủ"}), 404
        
    # Ghi lại log kiểm toán hành vi truy cập tệp
    write_audit_log("FILE_DOWNLOAD", f"User '{request.user}' requested encrypted blob for file_id '{file_id}'.")
    return send_file(file_path, mimetype='application/octet-stream')

@app.route('/files/delete/<file_id>', methods=['DELETE'])
@require_auth
def delete_file(file_id):
    """Xóa file khỏi cơ sở dữ liệu và ổ đĩa sau khi client tải và giải mã thành công"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Xác thực tệp và kiểm tra quyền hạn xóa (chỉ người nhận hoặc người gửi mới có quyền)
    cursor.execute("SELECT owner, target_group FROM files WHERE file_id = ?", (file_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Không tìm thấy tệp tin"}), 404
        
    if row[0] != request.user and row[1] != request.user:
        conn.close()
        return jsonify({"error": "Quyền truy cập bị từ chối"}), 403

    # Tiến hành xóa trong Database
    cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
    conn.commit()
    conn.close()

    # Tiến hành xóa file blob vật lý trong thư mục storage
    file_path = os.path.join(STORAGE_DIR, file_id)
    if os.path.exists(file_path):
        os.remove(file_path)

    write_audit_log("FILE_PURGE", f"Tệp tin file_id '{file_id}' đã được xóa hoàn toàn khỏi hệ thống bởi '{request.user}'.")
    return jsonify({"message": "Đã xóa tệp tin khỏi danh sách chờ"}), 200
if __name__ == '__main__':
    init_system()
    app.run(host='0.0.0.0', port=5003)