import psycopg2
import pandas as pd
import warnings

# Bỏ qua các cảnh báo không cần thiết của pandas khi dùng psycopg2 thuần
warnings.filterwarnings('ignore', category=UserWarning)

# Thông tin kết nối tới PostgreSQL (qua cổng đã ánh xạ ra máy host)
DB_HOST = "127.0.0.1"
DB_PORT = "5432"
DB_NAME = "secure_file_sharing"
DB_USER = "doan_user"
DB_PASS = "123456"

def export_db_to_excel(output_file="database_export.xlsx"):
    try:
        print("[*] Đang kết nối tới Database...")
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        cursor = conn.cursor()

        # 1. Lấy danh sách tất cả các bảng trong database
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        tables = [row[0] for row in cursor.fetchall()]

        if not tables:
            print("[-] Không tìm thấy bảng nào trong cơ sở dữ liệu. Bạn đã chạy server chưa?")
            return

        print(f"[*] Tìm thấy {len(tables)} bảng: {', '.join(tables)}")

        # 2. Tạo file Excel và ghi từng bảng vào từng Sheet
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            for table_name in tables:
                print(f"    -> Đang xuất dữ liệu bảng: {table_name}...")
                
                # Truy vấn toàn bộ dữ liệu của bảng
                df = pd.read_sql_query(f'SELECT * FROM "{table_name}"', conn)
                
                # Xử lý đặc biệt: Chuyển dữ liệu nhị phân (BYTEA/memoryview) thành chuỗi Hex
                # Excel không hỗ trợ ghi trực tiếp các bytes thô (như khóa mã hóa)
                for col in df.columns:
                    df[col] = df[col].apply(
                        lambda x: x.hex() if isinstance(x, (bytes, bytearray, memoryview)) else x
                    )
                
                # Ghi vào Sheet tương ứng
                df.to_excel(writer, sheet_name=table_name, index=False)

        print(f"\n[+] THÀNH CÔNG! Đã xuất toàn bộ dữ liệu ra file: {output_file}")

    except psycopg2.OperationalError:
        print("\n[-] LỖI KẾT NỐI: Không thể kết nối tới Database.")
        print("    Vui lòng kiểm tra xem container 'postgres_db' đã chạy chưa (docker-compose ps).")
    except Exception as e:
        print(f"\n[-] Có lỗi bất ngờ xảy ra: {str(e)}")
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    export_db_to_excel()