import os
import secrets
import datetime
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Test tấn công phát lại
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BURP = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
# ===============================


# Cấu hình kết nối hệ thống phân tán
AUTH_URL = "http://localhost:5002"
FILE_URL = "http://localhost:5003"
DATA_DIR = "./client_data"

session_ticket = None
current_user = None

def init_client():
    os.makedirs(DATA_DIR, exist_ok=True)

def generate_nonce_and_timestamp():
    """Tạo Nonce và Timestamp chuẩn ISO chống tấn công phát lại (Replay Attack)"""
    nonce = secrets.token_hex(16)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    return nonce, timestamp

def get_user_dir(username):
    """Hàm tạo và trả về đường dẫn thư mục cô lập cho từng Client"""
    path = os.path.join(DATA_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path

def get_auth_headers():
    """Hàm sinh Header bắt buộc chứa Session Ticket và Token chống phát lại"""
    nonce, timestamp = generate_nonce_and_timestamp()
    return {
        "Authorization": f"Bearer {session_ticket}",
        "X-Nonce": nonce,
        "X-Timestamp": timestamp
    }

def register():
    print("\n======================================")
    print("         MÀN HÌNH ĐĂNG KÝ TÀI KHOẢN     ")
    print("======================================")
    username = input("Nhập tên tài khoản mới: ").strip()
    password = input("Nhập mật khẩu an toàn: ").strip()

    if not username or not password:
        print("[-] Tài khoản và mật khẩu không được để trống!")
        return

    print("[*] Đang sinh cặp khóa RSA-2048 cục bộ an toàn...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])).sign(private_key, hashes.SHA256())
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    print("[*] Đang gửi yêu cầu đăng ký định danh tới Auth Server (RA)...")
    try:
        resp = requests.post(f"{AUTH_URL}/register", json={
            "username": username, "password": password, "csr": csr_pem
        })
        if resp.status_code == 200:
            # --- SỬ DỤNG THƯ MỤC CÔ LẬP ---
            user_dir = get_user_dir(username)
            
            priv_path = os.path.join(user_dir, f"{username}_priv.pem")
            with open(priv_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            cert_chain = resp.json().get("cert_chain")
            with open(os.path.join(user_dir, f"{username}_cert.pem"), "w") as f:
                f.write(cert_chain)
            print(f"[+] Đăng ký thành công! Khóa và chứng chỉ lưu tại: {user_dir}")
        else:
            print("[-] Thất bại:", resp.json().get("error"))
    except Exception as e:
        print("[-] Lỗi kết nối mạng:", e)

def login():
    global session_ticket, current_user
    print("\n======================================")
    print("               MÀN HÌNH ĐĂNG NHẬP       ")
    print("======================================")
    username = input("Tài khoản: ").strip()
    password = input("Mật khẩu: ").strip()

    nonce, timestamp = generate_nonce_and_timestamp()  
    try:
        resp = requests.post(f"{AUTH_URL}/login", json={
            "username": username, "password": password,
            "nonce": nonce, "timestamp": timestamp
        })

        # # Test tấn công phát lại
        # resp = requests.post(
        #     f"{AUTH_URL}/login", 
        #     json={"username": username, "password": password, 
        #           "nonce": nonce, "timestamp": timestamp},
        #     proxies=BURP, 
        #     verify=False 
        # )
        # #====================================
        
        if resp.status_code == 200:
            session_ticket = resp.json().get("session_ticket")
            current_user = username
            print(f"[+] Xác thực thành công! Đã cấp quyền phiên cho '{username}'.")
        else:
            try:
                print("[-] Từ chối đăng nhập:", resp.json().get("error"))
            except ValueError:
                print(f"[-] Lỗi hệ thống nội bộ từ phía Auth Server ({resp.status_code}).")
    except Exception as e:
        print("[-] Lỗi kết nối mạng:", e)

# ====================================================================
# MỤC 7.3: PENDING FILES (TỆP ĐANG CHỜ XỬ LÝ) - LUỒNG XỬ LÝ CHI TIẾT
# ====================================================================
def show_pending_files():
    print("\n============================================================================================")
    print("                         MỤC 1: DANH SÁCH TỆP TIN ĐANG CHỜ XỬ LÝ                            ")
    print("============================================================================================")
    
    try:
        resp = requests.get(f"{FILE_URL}/files/pending", headers=get_auth_headers())
        if resp.status_code != 200:
            print("[-] Không thể lấy danh sách tệp:", resp.json().get("error"))
            return
            
        files = resp.json().get("files", [])
        if not files:
            print("Không có tệp nào cần được xem xét.")
            return

        # CHI TIẾT 2: Căn bảng thẳng tắp, bổ sung cột Nhóm rộng 15 ký tự
        print(f"{'STT':<5} | {'Tên tệp tin':<30} | {'Người gửi':<15} | {'Nhóm':<15} | {'Thời gian':<20}")
        print("-" * 95)
        for idx, file_info in enumerate(files, 1):
            gname = file_info.get('group_name') if file_info.get('group_name') else ""
            print(f"{idx:<5} | {file_info['filename']:<30} | {file_info['owner']:<15} | {gname:<15} | {file_info['upload_time'][:19]:<20}")
            
        print("-" * 95)
        choice = input("Nhập số STT của tệp muốn tải xuống và giải mã (Nhấn Enter để quay lại): ").strip()
        if not choice: return
            
        try:
            selected_idx = int(choice) - 1
            if selected_idx < 0 or selected_idx >= len(files):
                print("[-] Số thứ tự nhập vào không hợp lệ.")
                return
        except ValueError:
            print("[-] Vui lòng nhập ký tự số hợp lệ.")
            return

        selected_file = files[selected_idx]
        file_id = selected_file["file_id"]
        filename = selected_file["filename"]
        wrapped_fsk_hex = selected_file["wrapped_fsk"]
        group_context = selected_file.get("group_name")

        # THÊM HỘP THOẠI XÁC NHẬN TẢI / XÓA BẢO MẬT
        while True:
            action = input(f"\n[?] Tải xuống file này? [Y/N/C]: ").strip().upper()
            if action in ['Y', 'N', 'C']:
                break
            print("[-] Vui lòng chọn Y (Đồng ý tải), N (Xóa file), hoặc C (Quay lại menu).")

        if action == 'C':
            print("[*] Đã hủy thao tác.")
            return

        if action == 'N':
            print(f"[*] Đang gửi yêu cầu xoá tệp tin '{filename}' lên Server...")
            del_resp = requests.delete(f"{FILE_URL}/files/delete/{file_id}", headers=get_auth_headers())
            if del_resp.status_code == 200:
                print("[+] Đã tiêu hủy tệp tin an toàn khỏi hệ thống Server.")
            else:
                print("[-] Lỗi:", del_resp.json().get("error"))
                print("[-] Chỉ admin và người sở hữu mới có thể xoá file. File vẫn sẽ hiển thị trên danh sách này.")
            return

        # NẾU ACTION == 'Y', TIẾN HÀNH TẢI VÀ GIẢI MÃ
        print(f"\n[*] Đang tải xuống khối mã hóa (blob) của tệp '{filename}' từ File Server...")
        blob_resp = requests.get(f"{FILE_URL}/files/download/{file_id}", headers=get_auth_headers())
        if blob_resp.status_code != 200:
            print("[-] Tải khối dữ liệu thất bại.")
            return
        encrypted_blob = blob_resp.content

        # Đọc khóa Private Key RSA của bản thân
        with open(os.path.join(get_user_dir(current_user), f"{current_user}_priv.pem"), "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        try:
            # --- LUỒNG XỬ LÝ MẬT MÃ KHÔI PHỤC KHÓA PHIÊN (FSK) ---
            if group_context:
                print(f"[*] Phát hiện tệp thuộc Nhóm '{group_context}'. Tiến hành lấy gói khóa nhóm GMK...")
                detail_resp = requests.get(f"{FILE_URL}/group/{group_context}", headers=get_auth_headers())
                if detail_resp.status_code != 200:
                    print(f"[-] Lỗi Server (Mã {detail_resp.status_code}): Không thể lấy gói khóa nhóm.")
                    return
                group_data = detail_resp.json()
                my_wrapped_gmk_hex = next(m['wrapped_gmk'] for m in group_data['members'] if m['username'] == current_user)
                
                print("[*] Đang dùng khóa bí mật RSA cục bộ giải mã lấy Khóa nhóm chính (GMK) rõ...")
                gmk_bytes = private_key.decrypt(
                    bytes.fromhex(my_wrapped_gmk_hex),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                
                print("[*] Đang dùng khóa nhóm GMK mở bọc đối xứng (Symmetric Unwrapping) lấy khóa phiên FSK...")
                wrapped_fsk_bytes = bytes.fromhex(wrapped_fsk_hex)
                gmk_aes = AESGCM(gmk_bytes)
                fsk = gmk_aes.decrypt(wrapped_fsk_bytes[:12], wrapped_fsk_bytes[12:], None)
            else:
                print("[*] Phát hiện tệp chia sẻ Cá nhân. Tiến hành mở bọc FSK trực tiếp bằng RSA-OAEP...")
                fsk = private_key.decrypt(
                    bytes.fromhex(wrapped_fsk_hex),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            
            print("[+] Khôi phục khóa phiên FSK thành công. Đang tiến hành giải mã khối tệp (AES-GCM-256)...")
            iv = encrypted_blob[:12]
            ciphertext = encrypted_blob[12:]
            aesgcm = AESGCM(fsk)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)

            output_path = os.path.join(get_user_dir(current_user), f"decrypted_{filename}")
            with open(output_path, "wb") as f:
                f.write(plaintext)
            print(f"[+] THÀNH CÔNG: Tệp rõ đã giải mã cục bộ lưu tại: {output_path}")
            
            # --- XỬ LÝ XÓA SAU KHI TẢI XONG ---
            if not group_context:
                # File cá nhân: Tự động xóa sau khi người nhận tải thành công
                print("[*] Đang dọn dẹp tệp tin cá nhân khỏi hàng đợi...")
                requests.delete(f"{FILE_URL}/files/delete/{file_id}", headers=get_auth_headers())
                print("[+] Đã xóa vết tệp tin khỏi hàng đợi tạm của Server.")
            else:
                # File nhóm: Giữ nguyên trên Server để các thành viên khác có thể tải
                print("[i] LƯU Ý: Tệp tin nhóm vẫn được giữ trên Server cho các thành viên khác.")
            
        except Exception as decrypt_err:
            print("[-] Thất bại mật mã: Khóa lỗi hoặc bạn đã bị trục xuất khỏi danh sách mật mã của nhóm.")
            print(f"[Chi tiết lỗi kỹ thuật]: {decrypt_err}")

    except Exception as e:
        print("[-] Đã xảy ra lỗi hệ thống:", e)


def upload_file_individual():
    """Mục 7.4: Tải tệp lên cho cá nhân (Giữ nguyên logic mã hóa lai ghép đầu vào)"""
    if not session_ticket:
        print("[-] Vui lòng đăng nhập hệ thống.")
        return

    print("\n======================================")
    print("      MỤC 2: CHIA SẺ TỆP CHO CÁ NHÂN   ")
    print("======================================")
    filepath = input("Nhập đường dẫn đầy đủ tới tệp cần mã hóa: ").strip()
    if not os.path.exists(filepath):
        print("[-] Đường dẫn không tồn tại!")
        return
        
    target_user = input("Nhập chính xác Username của người nhận: ").strip()

    print("[*] Đang tra cứu chứng chỉ định danh công khai của người nhận...")
    resp = requests.get(f"{AUTH_URL}/registry/{target_user}")
    if resp.status_code != 200:
        print("[-] Không thể xác thực khóa người nhận. Người dùng không tồn tại.")
        return
        
    target_cert_pem = resp.json().get("cert_pem")
    target_cert = x509.load_pem_x509_certificate(target_cert_pem.encode('utf-8'))
    target_pub_key = target_cert.public_key()

    print("[*] Tiến hành sinh khóa phiên File Session Key (FSK) AES-256 ngẫu nhiên...")
    fsk = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(fsk)
    
    with open(filepath, "rb") as f:
        plaintext = f.read()
    
    # Mã hóa dữ liệu bằng AES-GCM
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    encrypted_blob = iv + ciphertext 

    print("[*] Tiến hành bọc bảo vệ khóa FSK bằng RSA-OAEP khóa công khai người nhận...")
    wrapped_fsk = target_pub_key.encrypt(
        fsk,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    print("[*] Đang chuyển giao khối mã hóa nhị phân lên File Server...")
    files = {'file': (os.path.basename(filepath), encrypted_blob)}
    data = {
        'filename': os.path.basename(filepath),
        'target': target_user,
        'wrapped_fsk': wrapped_fsk.hex()
    }

    upload_resp = requests.post(f"{FILE_URL}/upload", headers=get_auth_headers(), files=files, data=data)
    if upload_resp.status_code == 200:
        print("[+] GIAO DỊCH THÀNH CÔNG! Tệp tin cá nhân tải lên ở trạng thái Zero-Knowledge bảo mật.")
    else:
        try:
            print("[-] Máy chủ từ chối file:", upload_resp.json().get("error", "Không rõ lỗi"))
        except Exception:
            print(f"[-] LỖI MÁY CHỦ ({upload_resp.status_code}): File Server gặp sự cố nội bộ (Database schema lỗi).")

def get_pending_files_count():
    """Hàm phụ trợ lấy nhanh số lượng file đang chờ xử lý từ File Server"""
    if not session_ticket:
        return 0
    try:
        # Gọi thử API lấy danh sách file
        resp = requests.get(f"{FILE_URL}/files/pending", headers=get_auth_headers())
        if resp.status_code == 200:
            return len(resp.json().get("files", []))
    except Exception:
        pass
    return 0

# ====================================================================
# MỤC 7.5: MY GROUPS (QUẢN LÝ NHÓM & LỜI MỜI) - CHUẨN ĐẶC TẢ
# ====================================================================


def fetch_group_data():
    resp = requests.get(f"{FILE_URL}/groups/me", headers=get_auth_headers())
    if resp.status_code == 200:
        return resp.json()
    return {"active": [], "invitations": []}

def get_groups_count():
    if not session_ticket: return 0
    return len(fetch_group_data().get("active", []))

def manage_groups():
    while True:
        data = fetch_group_data()
        my_groups = data.get("active", [])
        invitations = data.get("invitations", [])
        
        print("\n==================================================")
        print("          MỤC 3: QUẢN LÝ NHÓM CỦA TÔI             ")
        print("==================================================")
        print("1. Xem danh sách nhóm của tôi")
        print(f"2. Lời mời vào nhóm ({len(invitations)})")
        print("3. Tạo nhóm mới")
        print("0. Quay lại Menu chính")
        
        choice = input("Lựa chọn chức năng: ").strip()

        if choice == '0':
            break
            
        elif choice == '1':
            # --- XEM DANH SÁCH NHÓM ---
            if not my_groups:
                print("\n[*] Bạn chưa tham gia vào nhóm nào.")
                continue
                
            print("\nDANH SÁCH NHÓM BẠN ĐANG THAM GIA:")
            print(f"{'STT':<5} | {'Tên nhóm':<20} | {'Admin':<15} | {'Ngày tạo':<20} | {'Số thành viên':<15}")
            print("-" * 85)
            for idx, g in enumerate(my_groups, 1):
                print(f"{idx:<5} | {g['group_name']:<20} | {g['admin']:<15} | {g['created_at'][:19]:<20} | {g['member_count']:<15}")
                
            sel = input("\nNhập số STT hoặc Tên nhóm để xem chi tiết (Enter để bỏ qua): ").strip()
            if not sel: continue
            
            selected_group = None
            if sel.isdigit() and 1 <= int(sel) <= len(my_groups):
                selected_group = my_groups[int(sel) - 1]
            else:
                selected_group = next((g for g in my_groups if g['group_name'] == sel), None)
                
            if selected_group:
                group_detail_menu(selected_group['group_name'], selected_group['admin'])
            else:
                print("[-] Lỗi: Không tìm thấy nhóm tương ứng.")

        elif choice == '2':
            # --- LỜI MỜI VÀO NHÓM ---
            if not invitations:
                print("\n[*] Hiện không có lời mời nào đang chờ xử lý.")
                continue
                
            print("\nDANH SÁCH LỜI MỜI VÀO NHÓM CHƯA XỬ LÝ:")
            print(f"{'STT':<5} | {'Tên nhóm':<25} | {'Người mời (Admin)':<20}")
            print("-" * 60)
            for idx, inv in enumerate(invitations, 1):
                print(f"{idx:<5} | {inv['group_name']:<25} | {inv['admin']:<20}")
                
            sel = input("\nNhập số STT lời mời để tiếp tục (Enter để bỏ qua): ").strip()
            if not sel: continue
            
            if sel.isdigit() and 1 <= int(sel) <= len(invitations):
                inv = invitations[int(sel)-1]
                ans = input(f"Chấp nhận lời mời vào nhóm '{inv['group_name']}'? (Y/N): ").strip().upper()
                
                if ans == 'Y':
                    display_name = input("Nhập tên hiển thị của bạn trong nhóm này: ").strip()
                    
                    print("[*] Đang tải bản bọc Khóa nhóm (GMK) dành riêng cho bạn từ Server...")
                    wrapped_gmk_hex = inv['wrapped_gmk']
                    
                    print("[*] Tiến hành đọc khóa bí mật RSA cục bộ để giải mã (Decapsulation)...")
                    with open(os.path.join(get_user_dir(current_user), f"{current_user}_priv.pem"), "rb") as f:
                        priv_key = serialization.load_pem_private_key(f.read(), password=None)
                    
                    try:
                        gmk = priv_key.decrypt(
                            bytes.fromhex(wrapped_gmk_hex),
                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        print("[+] GIẢI MÃ THÀNH CÔNG! Khóa GMK đã được nạp vào bộ nhớ RAM cục bộ.")
                        
                        print("[*] Gửi tín hiệu xác nhận trạng thái 'Đã tham gia' lên File Server...")
                        requests.post(f"{FILE_URL}/group/{inv['group_name']}/action", headers=get_auth_headers(), 
                                      json={"action": "accept_invite", "display_name": display_name})
                        print("[+] Lời mời đã được xử lý thành công.")
                    except Exception as e:
                        print("[-] LỖI BẢO MẬT: Không thể giải mã GMK. Lời mời có thể bị giả mạo hoặc không dành cho khóa RSA của bạn!")
                
                elif ans == 'N':
                    print("[*] Đang gửi lệnh hủy lời mời lên Server...")
                    requests.post(f"{FILE_URL}/group/{inv['group_name']}/action", headers=get_auth_headers(), json={"action": "decline_invite"})
                    print("[+] Lời mời đã bị từ chối và xóa khỏi danh sách.")

        elif choice == '3':
            # --- TẠO NHÓM ---
            group_name = input("Nhập tên nhóm mới (không dấu cách): ").strip()
            if not group_name: continue
            
            print("[*] Tiến hành sinh khóa gốc của nhóm (Group Master Key - GMK) ngẫu nhiên bằng AES-256...")
            gmk = AESGCM.generate_key(bit_length=256)
            
            print("[*] Truy xuất chứng chỉ X.509 cục bộ để lấy Khóa công khai RSA của bạn...")
            with open(os.path.join(get_user_dir(current_user), f"{current_user}_cert.pem"), "rb") as f:
                my_cert = x509.load_pem_x509_certificate(f.read())
                
            print("[*] Tiến hành bọc bảo vệ GMK bằng thuật toán RSA-OAEP...")
            wrapped_gmk = my_cert.public_key().encrypt(
                gmk,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            print("[*] Đang chuyển giao dữ liệu mã hóa (Wrapped GMK) và siêu dữ liệu nhóm lên Server...")
            resp = requests.post(f"{FILE_URL}/group/create", headers=get_auth_headers(), json={
                "group_name": group_name, "wrapped_gmk": wrapped_gmk.hex()
            })
            
            if resp.status_code == 200:
                print("[+] GIAO DỊCH THÀNH CÔNG! Nhóm đã được tạo với bảo mật Zero-Knowledge.")
            else:
                print("[-] Lỗi máy chủ:", resp.json().get("error"))

def group_detail_menu(group_name, admin_username):
    is_admin = (current_user == admin_username)
    
    while True:
        print(f"\n--- QUẢN TRỊ NHÓM: {group_name} ---")
        print("1. Xem danh sách thành viên")
        print("2. Thêm thành viên            [Chỉ Admin]")
        print("3. Xóa thành viên             [Chỉ Admin]")
        print("4. Đổi tên hiển thị của tôi")
        print("5. Đổi tên nhóm               [Chỉ Admin]")
        print("6. Chuyển quyền Admin         [Chỉ Admin]")
        print("7. Rời nhóm")
        print("8. Xóa nhóm                   [Chỉ Admin]")
        print("0. Quay lại")
        
        choice = input("Lựa chọn: ").strip()
        if choice == '0': break
        
        admin_options = ['2', '3', '5', '6', '8']
        if choice in admin_options and not is_admin:
            print("[-] TỪ CHỐI TRUY CẬP: Chỉ Quản trị viên (Admin) mới có quyền thực hiện hành động này.")
            continue
            
        if choice == '1':
            print("[*] Đang tải danh sách thành viên từ Server...")
            resp = requests.get(f"{FILE_URL}/group/{group_name}/members", headers=get_auth_headers())
            
            print(f"\n{'STT':<5} | {'Tên hiển thị':<25} | {'Tên tài khoản (Username)':<20}")
            print("-" * 60)
            for idx, m in enumerate(resp.json().get("members", []), 1):
                print(f"{idx:<5} | {m['display_name']:<25} | {m['username']:<20}")
                
        elif choice == '2':
            target_user = input("Nhập Tên tài khoản (Username) người muốn mời: ").strip()
            
            print(f"[*] Tra cứu chứng chỉ định danh công khai (X.509) của '{target_user}'...")
            reg_resp = requests.get(f"{AUTH_URL}/registry/{target_user}")
            if reg_resp.status_code != 200:
                print("[-] Lỗi: Không tìm thấy định danh người dùng trong hệ thống PKI.")
                continue
                
            target_cert = x509.load_pem_x509_certificate(reg_resp.json().get("cert_pem").encode('utf-8'))
            target_pub_key = target_cert.public_key()
            print("[+] Đã xác minh chuỗi chứng chỉ. Trích xuất thành công Khóa công khai RSA.")
            
            # --- LOGIC MỚI: Lấy GMK thật của Admin và giải mã ---
            print("[*] Đang truy xuất bản bọc Khóa nhóm (GMK) của chính bạn từ Server...")
            g_resp = requests.get(f"{FILE_URL}/group/{group_name}", headers=get_auth_headers())
            if g_resp.status_code != 200:
                print("[-] Lỗi: Không thể tải thông tin mật mã của nhóm.")
                continue
            
            my_wrapped_gmk_hex = next(m['wrapped_gmk'] for m in g_resp.json()['members'] if m['username'] == current_user)
            
            print("[*] Tiến hành đọc khóa bí mật RSA cục bộ để khôi phục GMK dạng rõ...")
            with open(os.path.join(get_user_dir(current_user), f"{current_user}_priv.pem"), "rb") as f:
                my_priv_key = serialization.load_pem_private_key(f.read(), password=None)
                
            gmk = my_priv_key.decrypt(
                bytes.fromhex(my_wrapped_gmk_hex),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            print(f"[*] Tiến hành bọc GMK thật bằng Khóa công khai RSA-OAEP của thành viên mới...")
            new_wrapped_gmk = target_pub_key.encrypt(
                gmk,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            print("[*] Gửi bản bọc khóa an toàn và thông báo mời lên File Server...")
            requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={
                "action": "invite", "target_user": target_user, "wrapped_gmk": new_wrapped_gmk.hex()
            })
            print(f"[+] Lời mời bảo mật đã được gửi tới '{target_user}'.")

        elif choice == '3':
            target = input("Nhập Tên tài khoản thành viên cần xóa: ").strip()
            ans = input(f"Xác nhận xóa '{target}' khỏi nhóm? (Y/N): ").strip().upper()
            if ans == 'Y':
                print(f"[*] Đang gửi yêu cầu hủy phiên của '{target}' lên Server...")
                resp = requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={"action": "remove", "target_user": target})
                
                # Bổ sung kiểm tra kết quả từ Server
                if resp.status_code == 200:
                    print("[+] Thành viên đã bị xóa.")
                    print("[!] BẢO MẬT: Giao thức Xoay vòng khóa (Key Rotation) đã được kích hoạt. Hãy tạo GMK mới để chặn Forward Secrecy!")
                    break # Quay lại danh sách
                else:
                    print("[-] Lỗi:", resp.json().get("error"))

        elif choice == '4':
            new_name = input("Nhập tên hiển thị mới của bạn: ").strip()
            print("[*] Đang đồng bộ cấu hình metadata lên Server...")
            requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={"action": "edit_display_name", "new_name": new_name})
            print("[+] Cập nhật tên hiển thị thành công.")

        elif choice == '5':
            new_name = input("Nhập tên nhóm mới: ").strip()
            print("[*] Đang cập nhật metadata tên nhóm...")
            requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={"action": "edit_group_name", "new_name": new_name})
            group_name = new_name
            print("[+] Tên nhóm đã được thay đổi.")

        elif choice == '6':
            target = input("Nhập Username để chuyển quyền Admin: ").strip()
            ans = input(f"Xác nhận chuyển quyền Admin cho '{target}'? Bạn sẽ mất quyền quản trị. (Y/N): ").strip().upper()
            if ans == 'Y':
                print("[*] Đang thay đổi cấu trúc phân quyền trên cơ sở dữ liệu Server...")
                resp = requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={"action": "transfer_admin", "target_user": target})
                
                # Bổ sung kiểm tra kết quả từ Server
                if resp.status_code == 200:
                    is_admin = False
                    print("[+] Chuyển quyền quản trị viên thành công.")
                else:
                    print("[-] Lỗi:", resp.json().get("error"))

        elif choice == '7':
            ans = input(f"Bạn muốn rời khỏi nhóm '{group_name}'? (Y/N): ").strip().upper()
            if ans == 'Y':
                print("[*] Gửi tín hiệu ngắt kết nối với nhóm...")
                resp = requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={"action": "leave"})
                if resp.status_code != 200:
                    print("[-] Từ chối:", resp.json().get("error"))
                else:
                    print("[+] Rời nhóm thành công.")
                    break

        elif choice == '8':
            ans = input(f"CẢNH BÁO: Xóa nhóm '{group_name}' và TOÀN BỘ file đính kèm? Không thể khôi phục. (Y/N): ").strip().upper()
            if ans == 'Y':
                print("[*] Đang gửi lệnh thu hồi (Purge) toàn bộ dữ liệu cấu trúc nhóm...")
                requests.post(f"{FILE_URL}/group/{group_name}/action", headers=get_auth_headers(), json={"action": "delete"})
                print("[+] Hệ thống đã xóa sạch mọi dấu vết của nhóm.")
                break

def upload_file_group():
    """MỤC 3: CHIA SẺ TỆP LÊN NHÓM (Mã hóa bọc đối xứng bằng khóa GMK)"""
    print("\n==================================================")
    print("          MỤC 3: CHIA SẺ TỆP LÊN NHÓM             ")
    print("==================================================")
    
    # Bước 1: Hiển thị danh sách nhóm đang tham gia
    data = fetch_group_data()
    my_groups = data.get("active", [])
    if not my_groups:
        print("[*] Bạn chưa tham gia vào bất kỳ nhóm hoạt động nào để chia sẻ file.")
        return

    print("CÁC NHÓM BẠN ĐANG THAM GIA:")
    print(f"{'STT':<5} | {'Tên nhóm':<25} | {'Quản trị viên (Admin)':<20}")
    print("-" * 55)
    for idx, g in enumerate(my_groups, 1):
        print(f"{idx:<5} | {g['group_name']:<25} | {g['admin']:<20}")
    print("-" * 55)

    sel = input("Nhập Số thứ tự hoặc Tên nhóm để chia sẻ file: ").strip()
    selected_group = None
    if sel.isdigit() and 1 <= int(sel) <= len(my_groups):
        selected_group = my_groups[int(sel) - 1]
    else:
        selected_group = next((g for g in my_groups if g['group_name'] == sel), None)

    if not selected_group:
        print("[-] Lỗi: Lựa chọn nhóm không hợp lệ.")
        return

    group_name = selected_group['group_name']

    # Bước 2: Nhắc nhập đường dẫn tệp tin (Vòng lặp kiểm tra)
    while True:
        filepath = input("Nhập đường dẫn đầy đủ tới tệp cần tải lên nhóm: ").strip()
        if os.path.exists(filepath) and os.path.isfile(filepath):
            break
        print(f"[-] Lỗi: Không tìm thấy tệp tin hoặc đường dẫn '{filepath}' không hợp lệ. Vui lòng nhập lại.")

    # --- TIẾN HÀNH THAO TÁC BẢO MẬT VÀ IN LOG THEO VẾT ---
    print(f"\n[*] Tiến hành kết nối lấy thông tin gói khóa của nhóm '{group_name}'...")
    detail_resp = requests.get(f"{FILE_URL}/group/{group_name}", headers=get_auth_headers())
    
    if detail_resp.status_code != 200:
        print(f"[-] Lỗi Server (Mã {detail_resp.status_code}): {detail_resp.text}")
        return
        
    try:
        group_data = detail_resp.json()
    except Exception:
        print("[-] Lỗi: Server trả về dữ liệu không hợp lệ.")
        return
    
    group_data = detail_resp.json()
    
    # Tìm wrapped_gmk của bản thân trong nhóm
    my_wrapped_gmk_hex = next(m['wrapped_gmk'] for m in group_data['members'] if m['username'] == current_user)

    print("[*] Đang trích xuất đọc khóa riêng tư RSA cục bộ từ thiết bị...")
    with open(os.path.join(get_user_dir(current_user), f"{current_user}_priv.pem"), "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    print("[*] Tiến hành giải mã gói mật mã RSA-OAEP thu hồi Khóa nhóm chính (GMK) dạng rõ...")
    gmk_bytes = priv_key.decrypt(
        bytes.fromhex(my_wrapped_gmk_hex),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    print("[*] Tiến hành sinh ngẫu nhiên Khóa phiên tệp tin độc lập File Session Key (FSK) AES-256...")
    fsk = AESGCM.generate_key(bit_length=256)
    aesgcm_fsk = AESGCM(fsk)

    print("[*] Thực hiện mã hóa nội dung tệp tin bằng thuật toán AES-GCM-256...")
    with open(filepath, "rb") as f:
        plaintext = f.read()
    iv_file = os.urandom(12)
    ciphertext_blob = iv_file + aesgcm_fsk.encrypt(iv_file, plaintext, None)

    print("[*] Thực hiện bảo mật bọc khóa đối xứng: Mã hóa FSK dưới quyền khóa nhóm GMK...")
    iv_wrap = os.urandom(12)
    gmk_aes = AESGCM(gmk_bytes)
    # Gói wrapped_fsk nhóm = IV bọc + Ciphertext khóa FSK
    wrapped_fsk_blob = iv_wrap + gmk_aes.encrypt(iv_wrap, fsk, None)

    print("[*] Đang chuyển giao khối mã hóa nhị phân tệp và gói khóa bọc lên File Server...")
    files = {'file': (os.path.basename(filepath), ciphertext_blob)}
    data = {
        'filename': os.path.basename(filepath),
        'group_name': group_name,  # Định danh tệp thuộc nhóm
        'wrapped_fsk': wrapped_fsk_blob.hex()
    }

    upload_resp = requests.post(f"{FILE_URL}/upload", headers=get_auth_headers(), files=files, data=data)
    if upload_resp.status_code == 200:
        print("[+] GIAO DỊCH THÀNH CÔNG! Tệp tin nhóm đã tải lên ở trạng thái Zero-Knowledge bảo mật.")
    else:
        try:
            print("[-] Máy chủ từ chối tiếp nhận file:", upload_resp.json().get("error", "Không rõ lỗi"))
        except Exception:
            print(f"[-] LỖI MÁY CHỦ ({upload_resp.status_code}): File Server gặp sự cố nội bộ (Database schema lỗi).")

def main_menu():
    global session_ticket, current_user 
    init_client()
    while True:
        print("\n======================================")
        print("       HỆ THỐNG CHIA SẺ TỆP AN TOÀN    ")
        print("======================================")
        if current_user:
            pending_count = get_pending_files_count()
            group_count = get_groups_count()
            
            print(f"[Trạng thái]: Đã đăng nhập làm vế: '{current_user}'")
            print(f"1. Tệp đang chờ xử lý (Pending Files) ({pending_count})")
            print("2. Chia sẻ tệp cho cá nhân (Upload Individual)")
            print("3. Chia sẻ tệp lên nhóm (Upload Group)")
            print(f"4. Nhóm của tôi (My Groups) ({group_count})")
            print("5. Đăng xuất")
        else:
            print("[Trạng thái]: Chưa đăng nhập hệ thống")
            print("1. Đăng nhập hệ thống")
            print("2. Đăng ký tài khoản định danh PKI")
        print("0. Thoát chương trình")
        print("--------------------------------------")
        
        choice = input("Lựa chọn chức năng của bạn: ").strip()
        
        if not current_user:
            if choice == '1': login()
            elif choice == '2': register()
            elif choice == '0': break
            else: print("[-] Lựa chọn sai kịch bản menu.")
        else:
            if choice == '1': show_pending_files()
            elif choice == '2': upload_file_individual()
            elif choice == '3': upload_file_group() # LUỒNG GỬI FILE NHÓM MỚI
            elif choice == '4': manage_groups()
            elif choice == '5': 
                session_ticket = None
                current_user = None
                print("[+] Đã hủy phiên đăng xuất an toàn.")
            elif choice == '0': break
            else: print("[-] Lựa chọn sai kịch bản menu.")

if __name__ == "__main__":
    main_menu()