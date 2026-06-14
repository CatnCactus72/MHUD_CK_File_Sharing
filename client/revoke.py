import requests

CA_SERVER_URL = "http://localhost:5001"
TARGET_SERIAL = 697732878626295860741847730901337346232741232284  

payload = {
    "serial_number": TARGET_SERIAL,
    "reason": "keyCompromise"
}

print(f"[*] Đang gửi lệnh thu hồi chứng chỉ có Serial {TARGET_SERIAL} lên CA Server...")

try:
    resp = requests.post(f"{CA_SERVER_URL}/revoke_cert", json=payload)
    print(f"[+] Mã phản hồi từ Server: {resp.status_code}")
    
    # Kiểm tra nếu Server trả về kết quả thành công (200 OK) thì mới đọc JSON
    if resp.status_code == 200:
        print(f"[+] Nội dung phản hồi: {resp.json()}")
    else:
        print(f"[-] Thao tác thất bại. Lỗi từ Server: {resp.text}")
        
except requests.exceptions.ConnectionError:
    print("[-] Không thể kết nối tới CA Server. Hãy chắc chắn container ca_server đang chạy ở cổng 5001.")
except Exception as e:
    print(f"[-] Có lỗi xảy ra trong quá trình xử lý: {str(e)}")