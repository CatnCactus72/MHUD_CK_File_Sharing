from cryptography import x509
from cryptography.hazmat.backends import default_backend

cert_file = "client_data/nannhan/nannhan_cert.pem" 

with open(cert_file, "rb") as f:
    cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    print("\n[+] Trích xuất thành công!")
    print(f"Chủ sở hữu: {cert.subject}")
    print(f"Số Serial (Serial Number): {cert.serial_number}\n")