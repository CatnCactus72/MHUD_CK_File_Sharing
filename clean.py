import os
import shutil
import subprocess

def run_command(cmd):
    """Thực thi lệnh hệ thống và kiểm tra lỗi"""
    print(f"[*] Đang thực thi lệnh: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Cảnh báo lệnh gặp sự cố hoặc container đã dừng trước đó: {e}")

def clear_directory_contents(dir_path):
    """Xóa toàn bộ file và thư mục con bên trong một thư mục nhưng giữ nguyên thư mục cha"""
    if os.path.exists(dir_path):
        print(f"[*] Đang làm sạch phân vùng lưu trữ: {dir_path}")
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"[-] Không thể xóa mục {file_path}: {e}")
    else:
        os.makedirs(dir_path, exist_ok=True)

def recreate_empty_file(file_path):
    """Tạo lại file trống (0 byte) để làm chốt chặn bảo vệ liên kết Volume của Docker"""
    print(f"[*] Khởi tạo lại tệp tin trống bảo vệ volume: {file_path}")
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            pass # Tạo file 0 byte công khai
    except Exception as e:
        print(f"[-] Không thể thiết lập tệp trống {file_path}: {e}")

def main():
    print("======================================================================")
    print("   CHƯƠNG TRÌNH DỌN DẸP HỆ THỐNG PHÂN TÁN (ĐƯA VỀ TRẠNG THÁI SẠCH 0)  ")
    print("======================================================================")
    
    # Bước 1: Hạ tất cả container để giải phóng quyền đọc/ghi file của hệ điều hành
    run_command("docker-compose down")

    print("\n--- [1/4] Tiến hành dọn dẹp Node 1: CA Server ---")
    clear_directory_contents("./ca_server/root_ca")
    clear_directory_contents("./ca_server/intermediate_ca")

    print("\n--- [2/4] Tiến hành dọn dẹp Node 2: Auth Server ---")
    # Tái thiết lập các file cấu hình phẳng tránh bẫy tự tạo thư mục của Docker
    recreate_empty_file("./auth_server/nonce_store.db")
    recreate_empty_file("./auth_server/auth_priv_key.pem")
    recreate_empty_file("./auth_server/auth_pub_key.pem")

    print("\n--- [3/4] Tiến hành dọn dẹp Node 3: File Server ---")
    clear_directory_contents("./file_server/database")
    clear_directory_contents("./file_server/storage")
    clear_directory_contents("./file_server/logs")

    print("\n--- [4/4] Tiến hành dọn dẹp thiết bị cục bộ: Client ---")
    clear_directory_contents("./client/client_data")

    print("\n======================================================================")
    print("[+] THÀNH CÔNG: Toàn bộ hệ thống đã được đưa về trạng thái nguyên bản!")
    print("[*] Bây giờ bạn có thể tái tạo dữ liệu và chạy lại hệ thống bằng lệnh:")
    print("    docker-compose up --build -d")
    print("======================================================================")

if __name__ == "__main__":
    main()