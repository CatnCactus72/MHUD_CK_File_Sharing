import os
import datetime
from flask import Flask, request, jsonify, Response
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

app = Flask(__name__)

# Định nghĩa các đường dẫn thư mục chính xác theo mục 10 của Đặc tả
ROOT_CA_DIR = "./root_ca"
INT_CA_DIR = "./intermediate_ca"

# Đường dẫn tệp tin cụ thể
ROOT_KEY_PATH = os.path.join(ROOT_CA_DIR, "root_key.pem")
ROOT_CERT_PATH = os.path.join(ROOT_CA_DIR, "root_cert.pem")

INT_KEY_PATH = os.path.join(INT_CA_DIR, "int_key.pem")
INT_CERT_PATH = os.path.join(INT_CA_DIR, "int_cert.pem")
CRL_PATH = os.path.join(INT_CA_DIR, "crl.pem")


def generate_ca_hierarchy(is_root=True, issuer_key=None, issuer_name=None):
    """Hàm bổ trợ sinh cặp khóa RSA và chứng chỉ X.509"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    
    common_name = "SecureFS Root CA" if is_root else "SecureFS Intermediate CA"
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Sharing System"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    issuer = issuer_name if not is_root else subject
    signing_key = issuer_key if not is_root else private_key

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=1 if is_root else 0), critical=True)
    
    cert = builder.sign(private_key=signing_key, algorithm=hashes.SHA256())
    return private_key, cert, subject


def initialize_pki_at_first_boot():
    """Tự động kiểm tra và khởi tạo Root CA & Intermediate CA tại lần chạy đầu tiên"""
    os.makedirs(ROOT_CA_DIR, exist_ok=True)
    os.makedirs(INT_CA_DIR, exist_ok=True)

    if os.path.exists(ROOT_CERT_PATH) and os.path.exists(INT_CERT_PATH):
        print("[CA SERVER] Cấu trúc PKI đã tồn tại. Bỏ qua bước khởi tạo.")
        return

    print("[CA SERVER] Lần đầu khởi động hệ thống: Tiến hành tạo Root CA và Intermediate CA...")
    
    # 1. Khởi tạo cấu trúc dữ liệu cho tầng Root CA
    root_key, root_cert, root_subject = generate_ca_hierarchy(is_root=True)
    
    # 2. Khởi tạo cấu trúc dữ liệu cho tầng Intermediate CA (được ký bởi Root CA)
    int_key, int_cert, _ = generate_ca_hierarchy(is_root=False, issuer_key=root_key, issuer_name=root_subject)
    
    # 3. Lưu trữ thông tin phân vùng Root CA
    with open(ROOT_KEY_PATH, "wb") as f:
        f.write(root_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        
    # 4. Lưu trữ thông tin phân vùng Intermediate CA
    with open(INT_KEY_PATH, "wb") as f:
        f.write(int_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    with open(INT_CERT_PATH, "wb") as f:
        f.write(int_cert.public_bytes(serialization.Encoding.PEM))
        
    # 5. Khởi tạo danh sách thu hồi chứng chỉ (CRL) trống ban đầu thuộc quyền Intermediate CA
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(int_cert.subject)
    crl_builder = crl_builder.last_update(datetime.datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=7))
    crl = crl_builder.sign(private_key=int_key, algorithm=hashes.SHA256())
    
    with open(CRL_PATH, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print("[CA SERVER] Hệ thống PKI đã thiết lập thành công.")


def load_pki_credentials():
    """Hàm tải các chứng chỉ cần thiết lên bộ nhớ để phục vụ API ký số"""
    with open(INT_KEY_PATH, "rb") as f:
        int_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(INT_CERT_PATH, "rb") as f:
        int_cert = x509.load_pem_x509_certificate(f.read())
    with open(ROOT_CERT_PATH, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    return int_key, int_cert, root_cert


@app.route('/issue_cert', methods=['POST'])
def issue_cert():
    """
    Endpoint tiếp nhận CSR phục vụ đăng ký người dùng mới.
    Trả về toàn bộ chuỗi chứng chỉ: User Cert -> Intermediate Cert -> Root Cert
    """
    try:
        data = request.json
        csr_pem = data.get('csr')
        if not csr_pem:
            return jsonify({"error": "Yêu cầu thiếu dữ liệu CSR"}), 400

        # Đọc và xác thực chữ ký của CSR gửi lên
        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        if not csr.is_signature_valid:
            return jsonify({"error": "Chữ ký trên CSR không hợp lệ"}), 400

        # Tải cấu hình khóa từ bộ nhớ bảo mật của thư mục cục bộ
        int_key, int_cert, root_cert = load_pki_credentials()

        # Tiến hành ký cấp phát chứng chỉ người dùng từ quyền Intermediate CA
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(int_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) # Hiệu lực 1 năm
        
        user_cert = builder.sign(private_key=int_key, algorithm=hashes.SHA256())

        # Gộp toàn bộ dữ liệu thành một chuỗi chứng chỉ hoàn chỉnh (Chain Certificate)
        chain_pem = user_cert.public_bytes(serialization.Encoding.PEM) + \
                    int_cert.public_bytes(serialization.Encoding.PEM) + \
                    root_cert.public_bytes(serialization.Encoding.PEM)

        return jsonify({"cert_chain": chain_pem.decode('utf-8')}), 200

    except Exception as e:
        return jsonify({"error": f"Lỗi trong quá trình cấp phát: {str(e)}"}), 500


@app.route('/crl', methods=['GET'])
def get_crl():
    """Endpoint công khai để các Node và Client tải danh sách thu hồi chứng chỉ (CRL)"""
    try:
        with open(CRL_PATH, "rb") as f:
            crl_data = f.read()
        return Response(crl_data, mimetype='application/x-pem-file')
    except Exception as e:
        return jsonify({"error": "Không tìm thấy tệp danh sách thu hồi CRL"}), 404


if __name__ == '__main__':
    # Bước 1: Chạy tiến trình kiểm tra/khởi tạo thư mục dữ liệu root_ca và intermediate_ca khi container boot
    initialize_pki_at_first_boot()
    
    # Bước 2: Kích hoạt API Web Server lắng nghe trên cổng 5001
    app.run(host='0.0.0.0', port=5001)