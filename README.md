# Hệ Thống Chia Sẻ Tệp Tin Bảo Mật

> Đồ án môn học — Mật mã ứng dụng & An toàn thông tin  
> Mô hình Client–Server, triển khai hoàn toàn trên Docker

---

## Hướng dẫn cài đặt và chạy chương trình
- Sau khi cài đặt và chạy Docker, mở terminal tại thư mục gốc và chạy 2 lệnh sau:

* **docker-compose build**
* **docker-compose up -d**

- Sau khi các container được chạy thành công, mở terminal khác và chạy lệnh sau để chạy ứng dụng bên phía client:

* **cd client**
* **python client.py**

- Khi cần xoá hết toàn bộ dữ liệu, về thư mục gốc và chạy lệnh sau:

* **python clean.py**

- Để xuất ra các database có trong hệ thống hiện tại, chạy lệnh sau tại thư mục gốc:

* **python export_db.py**

## Mục lục

1. [Tổng quan dự án](#1-tổng-quan-dự-án)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Thiết kế mật mã học](#3-thiết-kế-mật-mã-học)
4. [Cơ sở dữ liệu](#4-cơ-sở-dữ-liệu)
5. [Hướng dẫn cài đặt & chạy](#5-hướng-dẫn-cài-đặt--chạy)
6. [Luồng hoạt động của ứng dụng](#6-luồng-hoạt-động-của-ứng-dụng)
7. [Cấu trúc thư mục dự án](#7-cấu-trúc-thư-mục-dự-án)
8. [Công cụ tiện ích](#8-công-cụ-tiện-ích)
9. [Bảng tổng hợp yêu cầu đã đạt](#9-bảng-tổng-hợp-yêu-cầu-đã-đạt)

---

## 1. Tổng quan dự án

Hệ thống cho phép người dùng chia sẻ tệp tin với nhau (theo cá nhân hoặc theo nhóm) với đảm bảo cốt lõi: **Server không thể đọc nội dung tệp tin**. Toàn bộ quá trình mã hóa và giải mã xảy ra hoàn toàn tại máy Client. Dữ liệu lưu trên Server chỉ là các khối mã hóa nhị phân (ciphertext) mà Server không có khóa để giải mã.

**Các tính năng chính:**

- Đăng ký tài khoản kèm cấp phát chứng chỉ số X.509 tự động qua hệ thống PKI hai tầng
- Đăng nhập một lần (SSO) với Session Ticket ký số RS256, hiệu lực 2 giờ
- Chia sẻ tệp tin mã hóa đầu cuối cho cá nhân hoặc nhóm
- Quản lý nhóm với phân quyền Admin/Member rõ ràng
- Bảo vệ chống tấn công phát lại (Replay Attack) bằng cơ chế Nonce + Timestamp
- Ghi nhật ký kiểm toán (Audit Log) toàn bộ giao dịch hệ thống

---

## 2. Kiến trúc hệ thống

Hệ thống được triển khai trên **4 Docker container** giao tiếp qua mạng nội bộ `secure_net`:

```
┌─────────────────────────────────────────────────────────────────┐
│                        DOCKER NETWORK: secure_net               │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │  CA Server   │   │ Auth Server  │   │    File Server       │ │
│  │  Port: 5001  │◄──│  Port: 5002  │◄──│    Port: 5003        │ │
│  │  (PKI/CRL)   │   │ (SSO / KDC)  │   │ (Tệp tin & Nhóm)    │ │
│  └──────────────┘   └──────┬───────┘   └─────────┬────────────┘ │
│                            │                     │              │
│                     ┌──────▼─────────────────────▼───────────┐  │
│                     │        PostgreSQL (Port: 5432)          │  │
│                     │         secure_file_sharing DB          │  │
│                     └─────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
              ▲                    ▲
              │ HTTP               │ HTTP
              └────────┬───────────┘
                ┌──────┴──────┐
                │   Client    │
                │  (Terminal) │
                │  localhost  │
                └─────────────┘
```

### Node 1 — CA Server (Port 5001)

Container chuyên trách toàn bộ nghiệp vụ PKI (Public Key Infrastructure):

- Tự động khởi tạo chuỗi CA hai tầng tại lần boot đầu tiên:
  - **Root CA** (RSA-4096, tự ký, hiệu lực 10 năm)
  - **Intermediate CA** (RSA-4096, ký bởi Root CA, hiệu lực 10 năm)
- Tiếp nhận CSR từ Auth Server, ký và phát hành **chứng chỉ người dùng X.509** (RSA-2048, hiệu lực 1 năm) bằng Intermediate CA
- Trả về chuỗi chứng chỉ đầy đủ: `User Cert → Intermediate CA Cert → Root CA Cert`
- Quản lý và cung cấp **CRL (Certificate Revocation List)** qua endpoint công khai `/crl`

| Endpoint | Phương thức | Mô tả |
|---|---|---|
| `/issue_cert` | POST | Tiếp nhận CSR, ký và trả về chuỗi chứng chỉ |
| `/crl` | GET | Tải danh sách thu hồi chứng chỉ (CRL) |

### Node 2 — Auth Server (Port 5002)

Container xử lý xác thực danh tính người dùng (KDC/SSO):

- **Đăng ký**: Tiếp nhận thông tin và CSR của người dùng; đóng vai trò RA (Registration Authority) chuyển tiếp CSR đến CA Server; lưu hash mật khẩu (Werkzeug PBKDF2) và chuỗi chứng chỉ vào database
- **Đăng nhập**: Xác minh mật khẩu, kiểm tra CRL, phát hành **Session Ticket** dạng JWT (RS256) với trường `{username, iat, exp}` — hiệu lực 2 giờ
- **Nonce Store**: Lưu vết nonce đã sử dụng vào bảng `nonces` (PostgreSQL), TTL 5 phút, tự động dọn dẹp
- **Public Key Registry**: Cung cấp chứng chỉ X.509 của bất kỳ người dùng nào theo yêu cầu (để bên gửi trích xuất Public Key của bên nhận)

| Endpoint | Phương thức | Mô tả |
|---|---|---|
| `/register` | POST | Đăng ký tài khoản mới + yêu cầu CA cấp chứng chỉ |
| `/login` | POST | Xác thực và phát hành Session Ticket JWT |
| `/public_key` | GET | Lấy Public Key RSA của Auth Server (để File Server xác minh JWT) |
| `/registry/<username>` | GET | Lấy chứng chỉ X.509 của người dùng bất kỳ |

### Node 3 — File Server (Port 5003)

Container lưu trữ và quản lý toàn bộ tài nguyên:

- **Xác thực mọi request** qua decorator `@require_auth`: kiểm tra JWT (RS256 với Public Key lấy từ Auth Server), đồng thời kiểm tra Nonce + Timestamp chống Replay Attack
- **Lưu trữ blob mã hóa** trên ổ đĩa (`./storage/<file_id>`) — Server chỉ thấy ciphertext
- **Lưu trữ wrapped key** (`wrapped_fsk`, `wrapped_gmk`) trong database — Server không có khóa để giải mã
- **Quản lý nhóm**: tạo nhóm, mời thành viên, phân quyền Admin, lưu danh sách thành viên và trạng thái lời mời
- **Ghi Audit Log** tại `./logs/audit_log.txt` cho mọi giao dịch

| Endpoint | Phương thức | Mô tả |
|---|---|---|
| `/upload` | POST | Tải blob mã hóa + wrapped_fsk lên server |
| `/files/pending` | GET | Lấy danh sách tệp chờ xử lý |
| `/files/download/<file_id>` | GET | Tải blob nhị phân mã hóa |
| `/files/delete/<file_id>` | DELETE | Xóa tệp khỏi database và ổ đĩa |
| `/groups/me` | GET | Lấy danh sách nhóm (active) và lời mời (pending) |
| `/group/create` | POST | Tạo nhóm mới kèm wrapped GMK |
| `/group/<name>` | GET | Lấy thông tin nhóm + danh sách wrapped GMK thành viên |
| `/group/<name>/members` | GET | Lấy danh sách thành viên |
| `/group/<name>/action` | POST | Xử lý đa năng: mời, chấp nhận, từ chối, xóa, đổi tên, chuyển quyền, rời, xóa nhóm |

### Container PostgreSQL (Port 5432)

Database dùng chung cho cả Auth Server và File Server. Dữ liệu được bảo toàn qua Docker volume `pgdata`.

### Client (Terminal App)

Ứng dụng dòng lệnh chạy trên máy người dùng, **thành phần duy nhất tiếp xúc với dữ liệu rõ (plaintext)**:

- Sinh cặp khóa RSA-2048 và tạo CSR ngay trên máy cục bộ khi đăng ký
- Lưu trữ Private Key và chứng chỉ X.509 tại `./client_data/<username>/` (cô lập theo người dùng)
- Thực hiện toàn bộ mã hóa/giải mã AES-256-GCM và bọc khóa RSA-OAEP
- Gắn `Authorization: Bearer <JWT>`, `X-Nonce`, `X-Timestamp` vào mọi request gửi đến File Server

---

## 3. Thiết kế mật mã học

### 3.1 Phân cấp khóa

```
Root CA Key (RSA-4096, tự ký)
  └── Intermediate CA Key (RSA-4096, ký bởi Root CA)
        └── User Certificate (RSA-2048, X.509, ký bởi Intermediate CA)
                └── Group Master Key — GMK (AES-256, sinh ngẫu nhiên)
                          └── File Session Key — FSK (AES-256, sinh ngẫu nhiên)
                                    └── Nội dung tệp tin mã hóa (AES-256-GCM)
```

### 3.2 Mã hóa và tải tệp lên

#### Chia sẻ cho cá nhân

```
[CLIENT - BÊN GỬI]
1. Sinh FSK ngẫu nhiên (AES-256)
2. Mã hóa nội dung tệp:  IV(12B) || AES-256-GCM(FSK, plaintext)  →  encrypted_blob
3. Truy xuất cert X.509 của người nhận từ /registry/<username> (Auth Server)
4. Bọc FSK:  RSA-OAEP(PublicKey_người_nhận, FSK)  →  wrapped_fsk
5. Upload encrypted_blob + wrapped_fsk lên File Server
```

#### Chia sẻ lên nhóm

```
[CLIENT - BÊN GỬI]
1. Tải wrapped_gmk của bản thân từ File Server
2. Giải mã GMK:  RSA-OAEP-Decrypt(PrivateKey_mình, wrapped_gmk)  →  gmk (bytes rõ, trong RAM)
3. Sinh FSK ngẫu nhiên (AES-256)
4. Mã hóa nội dung tệp:  IV_file(12B) || AES-256-GCM(FSK, plaintext)  →  encrypted_blob
5. Bọc FSK bằng GMK:  IV_wrap(12B) || AES-256-GCM(GMK, FSK)  →  wrapped_fsk
6. Upload encrypted_blob + wrapped_fsk + group_name lên File Server
```

### 3.3 Tải tệp xuống và giải mã

#### Tệp cá nhân

```
[CLIENT - BÊN NHẬN]
1. Tải encrypted_blob và wrapped_fsk từ File Server
2. Giải mã FSK:  RSA-OAEP-Decrypt(PrivateKey_mình, wrapped_fsk)  →  fsk
3. Giải mã nội dung:  AES-256-GCM-Decrypt(FSK, IV, ciphertext)  →  plaintext
4. Lưu tệp rõ vào  client_data/<username>/decrypted_<filename>
5. Tự động xóa tệp khỏi hàng đợi trên Server (tệp cá nhân chỉ tải một lần)
```

#### Tệp nhóm

```
[CLIENT - THÀNH VIÊN NHÓM]
1. Tải encrypted_blob và wrapped_fsk từ File Server
2. Tải wrapped_gmk của bản thân từ thông tin nhóm (File Server)
3. Giải mã GMK:  RSA-OAEP-Decrypt(PrivateKey_mình, wrapped_gmk)  →  gmk
4. Giải mã FSK:  AES-256-GCM-Decrypt(GMK, IV_wrap, wrapped_fsk[12:])  →  fsk
5. Giải mã nội dung:  AES-256-GCM-Decrypt(FSK, IV_file, ciphertext)  →  plaintext
6. Lưu tệp rõ vào  client_data/<username>/decrypted_<filename>
7. Tệp nhóm vẫn giữ trên Server để các thành viên khác tiếp tục tải
```

### 3.4 Lưu trữ Group Master Key (GMK)

GMK **không bao giờ lưu dạng rõ** trên Server. Cơ chế lưu trữ thực tế:

- **Tạo nhóm**: Client sinh GMK ngẫu nhiên → mã hóa bằng RSA-OAEP với Public Key của chính mình → lưu `wrapped_gmk` vào bảng `group_members` của File Server
- **Mời thành viên**: Admin giải mã GMK bằng Private Key cục bộ → mã hóa lại bằng RSA-OAEP với Public Key của thành viên mới → lưu `wrapped_gmk` riêng cho thành viên mới vào database
- **Chấp nhận lời mời**: Client tải `wrapped_gmk` về → giải mã bằng Private Key → GMK tồn tại trong RAM phiên làm việc
- **Mỗi thành viên** có một bản `wrapped_gmk` riêng được mã hóa với Public Key của chính họ; Server không thể suy ra GMK từ bất kỳ bản nào

> **Lưu ý — Xoay vòng khóa (Key Rotation):** Khi Admin xóa thành viên, hệ thống hiển thị cảnh báo nhắc Admin cần tạo nhóm mới hoặc thực hiện xoay vòng GMK thủ công để đảm bảo thành viên bị xóa không giải mã được các tệp tải lên sau đó.

### 3.5 Bảo vệ chống Replay Attack (Nonce + Timestamp)

Mọi request gửi đến Auth Server và File Server đều bao gồm:

- **`X-Nonce`**: Chuỗi ngẫu nhiên 128-bit dạng hex, duy nhất mỗi request, sinh bởi `secrets.token_hex(16)`
- **`X-Timestamp`**: Thời điểm gửi request theo chuẩn ISO 8601 UTC

Server kiểm tra **hai bước tuần tự**:

1. Timestamp phải nằm trong cửa sổ ±5 phút so với giờ Server; nếu lệch → `403 Request timestamp out of window.`
2. Nonce chưa từng được dùng trước đó (tra cứu bảng `nonces` PostgreSQL); nếu trùng → `403 Replay Attack Detected: Nonce already used!`

Nonce hợp lệ được ghi vào database. Các nonce cũ hơn 5 phút được tự động xóa trước mỗi lần kiểm tra.

### 3.6 Xác thực Session Ticket (JWT RS256)

File Server xác minh mọi request qua decorator `@require_auth`:

1. Trích xuất `Authorization: Bearer <token>`, `X-Nonce`, `X-Timestamp` từ header
2. Kiểm tra Nonce + Timestamp (mục 3.5)
3. Tải Public Key của Auth Server từ `/public_key` (lazy-load, cache vào biến toàn cục)
4. Giải mã và xác minh JWT bằng `PyJWT` (thuật toán RS256)
5. Gắn `request.user = payload['username']` — mọi handler sau dùng để phân quyền

File Server **không liên hệ lại Auth Server** trong từng request; chỉ dùng Public Key đã cache để xác minh chữ ký JWT cục bộ.

### 3.7 Kiểm tra CRL khi đăng nhập

Tại bước đăng nhập, Auth Server:

1. Tải CRL từ CA Server (`/crl`)
2. Tải chứng chỉ X.509 của người dùng từ database
3. So sánh `serial_number` của chứng chỉ với từng mục trong CRL
4. Nếu khớp → trả về `403 Certificate revoked. Access denied.` và từ chối phát hành Ticket

---

## 4. Cơ sở dữ liệu

Database PostgreSQL `secure_file_sharing` chứa các bảng sau:

### Bảng `users` (Auth Server quản lý)

| Cột | Kiểu | Mô tả |
|---|---|---|
| `username` | TEXT (PK) | Tên đăng nhập |
| `password_hash` | TEXT | Hash mật khẩu (Werkzeug PBKDF2) |
| `cert_pem` | TEXT | Chuỗi chứng chỉ X.509 đầy đủ (PEM) |

### Bảng `nonces` (cả Auth Server và File Server)

| Cột | Kiểu | Mô tả |
|---|---|---|
| `nonce` | TEXT (PK) | Chuỗi nonce hex 128-bit |
| `timestamp` | TIMESTAMP | Thời điểm request (dùng để TTL cleanup) |

### Bảng `files` (File Server quản lý)

| Cột | Kiểu | Mô tả |
|---|---|---|
| `file_id` | TEXT (PK) | UUID duy nhất của tệp |
| `filename` | TEXT | Tên tệp gốc |
| `owner` | TEXT | Username người gửi |
| `target_group` | TEXT | Username người nhận (tệp cá nhân) |
| `group_name` | TEXT | Tên nhóm (tệp nhóm; NULL nếu là tệp cá nhân) |
| `wrapped_fsk` | TEXT | FSK đã bọc (hex): RSA-OAEP (cá nhân) hoặc AES-GCM (nhóm) |
| `upload_time` | TIMESTAMP | Thời điểm tải lên |

### Bảng `groups`

| Cột | Kiểu | Mô tả |
|---|---|---|
| `group_name` | TEXT (PK) | Tên nhóm (duy nhất) |
| `admin` | TEXT | Username Admin hiện tại |
| `created_at` | TIMESTAMP | Thời điểm tạo nhóm |

### Bảng `group_members`

| Cột | Kiểu | Mô tả |
|---|---|---|
| `group_name` | TEXT (PK) | Tên nhóm |
| `username` | TEXT (PK) | Username thành viên |
| `display_name` | TEXT | Tên hiển thị trong nhóm |
| `wrapped_gmk` | TEXT | GMK đã bọc bằng RSA-OAEP với Public Key của thành viên (hex) |
| `status` | TEXT | `'active'` (đang tham gia) hoặc `'pending'` (chờ chấp nhận lời mời) |

---

## 5. Hướng dẫn cài đặt & chạy

### Yêu cầu hệ thống

- **Docker** và **Docker Compose** (phiên bản ≥ 3.8)
- **Python 3.9+** (cho Client)
- Các port `5001`, `5002`, `5003`, `5432` chưa bị chiếm dụng trên máy host

### Bước 1 — Khởi động các Server

```bash
# Giải nén và vào thư mục dự án
cd MHUD_CK_File_Sharing

# Build image và khởi động 4 container
docker-compose up --build
```

Lần đầu chạy, CA Server sẽ tự động khởi tạo toàn bộ cấu trúc PKI và in:

```
[CA SERVER] Lần đầu khởi động hệ thống: Tiến hành tạo Root CA và Intermediate CA...
[CA SERVER] Hệ thống PKI đã thiết lập thành công.
[AUTH SERVER] Đang tiến hành tạo cặp khóa RSA ký Session Ticket tại thư mục gốc...
```

> **Lưu ý:** Nếu `auth_server` khởi động trước khi `postgres_db` sẵn sàng và báo lỗi kết nối database, hãy chạy:
> ```bash
> docker-compose restart auth_server
> ```
> Kiểm tra lại: `docker-compose ps` — 4 container đều phải ở trạng thái `Up`.

### Bước 2 — Cài đặt và chạy Client

```bash
# Mở terminal mới (giữ nguyên terminal server đang chạy)
cd MHUD_CK_File_Sharing/client

# Cài đặt thư viện Python
pip install -r ../requirements.txt

# Khởi động ứng dụng
python client.py
```

### Bước 3 — Sử dụng lần đầu

Màn hình chào hiện ra khi chưa đăng nhập:

```
======================================
       HỆ THỐNG CHIA SẺ TỆP AN TOÀN
======================================
[Trạng thái]: Chưa đăng nhập hệ thống
1. Đăng nhập hệ thống
2. Đăng ký tài khoản định danh PKI
0. Thoát chương trình
```

Chọn `2` để đăng ký. Hệ thống tự động sinh RSA-2048, gửi CSR đến CA và lưu chứng chỉ về máy.

---

## 6. Luồng hoạt động của ứng dụng

### 6.1 Đăng ký tài khoản

```
Client: Nhập username + password
     → Sinh cặp khóa RSA-2048 cục bộ + tạo CSR
     → Gửi {username, password, CSR} đến Auth Server /register
          Auth Server: Kiểm tra username trùng
                     → Chuyển CSR đến CA Server /issue_cert
               CA Server: Ký CSR bằng Intermediate CA → trả về cert_chain (PEM 3 tầng)
          Auth Server: Lưu {username, hash(password), cert_chain} vào DB
     → Client nhận cert_chain
     → Lưu private key  → client_data/<username>/<username>_priv.pem
     → Lưu cert chain   → client_data/<username>/<username>_cert.pem
     → In: "[+] Đăng ký thành công!"
```

### 6.2 Đăng nhập

```
Client: Nhập username + password
     → Sinh Nonce (128-bit hex) + Timestamp (ISO 8601 UTC)
     → Gửi {username, password, nonce, timestamp} đến Auth Server /login
          Auth Server: Kiểm tra Nonce + Timestamp (chống Replay Attack)
                     → Xác minh hash(password)
                     → Tải CRL từ CA Server, kiểm tra serial_number chứng chỉ
                     → Ký JWT RS256: payload {username, iat, exp=iat+2h}
     → Client nhận Session Ticket (JWT), lưu trong RAM
```

### 6.3 Menu chính (sau đăng nhập)

```
======================================
       HỆ THỐNG CHIA SẺ TỆP AN TOÀN
======================================
[Trạng thái]: Đã đăng nhập làm vế: 'username'
1. Tệp đang chờ xử lý (Pending Files) (N)
2. Chia sẻ tệp cho cá nhân (Upload Individual)
3. Chia sẻ tệp lên nhóm (Upload Group)
4. Nhóm của tôi (My Groups) (N)
5. Đăng xuất
0. Thoát chương trình
```

Số `(N)` hiển thị số lượng tệp đang chờ / số nhóm đang tham gia.

### 6.4 Tệp đang chờ xử lý (Pending Files)

Hiển thị bảng các tệp được chia sẻ đến bạn:

```
STT  | Tên tệp tin                    | Người gửi       | Nhóm            | Thời gian
-------------------------------------------------------------------------------------------------
1    | baocao.pdf                     | alice           | Nhom_KMA        | 2026-05-20 10:05:12
```

Sau khi chọn tệp, hệ thống hỏi `[Y/N/C]` (Tải xuống / Xóa / Quay lại):

- **Y**: Tải blob mã hóa → giải mã tự động → lưu file rõ tại `client_data/<username>/decrypted_<filename>`. Tệp cá nhân tự xóa khỏi Server sau khi tải thành công; tệp nhóm vẫn giữ trên Server cho thành viên khác.
- **N**: Xóa tệp khỏi hàng đợi không tải (người gửi hoặc Admin nhóm mới được xóa tệp nhóm; người gửi hoặc người nhận được xóa tệp cá nhân).

### 6.5 Chia sẻ tệp cho cá nhân

```
→ Nhập đường dẫn tệp nguồn trên máy cục bộ
→ Nhập Username người nhận
→ Truy xuất chứng chỉ X.509 người nhận từ Auth Server /registry/<username>
→ Trích xuất Public Key RSA của người nhận
→ Sinh FSK ngẫu nhiên → mã hóa tệp (AES-256-GCM)
→ Bọc FSK bằng RSA-OAEP với Public Key người nhận
→ Upload encrypted_blob + wrapped_fsk lên File Server
```

### 6.6 Chia sẻ tệp lên nhóm

```
→ Hiển thị danh sách nhóm đang tham gia, chọn nhóm đích
→ Nhập đường dẫn tệp nguồn
→ Tải wrapped_gmk của bản thân từ File Server
→ Giải mã GMK bằng Private Key RSA cục bộ (RSA-OAEP)
→ Sinh FSK ngẫu nhiên → mã hóa tệp (AES-256-GCM)
→ Bọc FSK bằng GMK (AES-256-GCM, IV 12 bytes)
→ Upload encrypted_blob + wrapped_fsk + group_name lên File Server
```

### 6.7 Quản lý nhóm

**Menu nhóm chính:**

```
1. Xem danh sách nhóm của tôi
2. Lời mời vào nhóm (N)
3. Tạo nhóm mới
0. Quay lại Menu chính
```

**Menu chi tiết nhóm:**

```
--- QUẢN TRỊ NHÓM: <tên_nhóm> ---
1. Xem danh sách thành viên
2. Thêm thành viên            [Chỉ Admin]
3. Xóa thành viên             [Chỉ Admin]
4. Đổi tên hiển thị của tôi
5. Đổi tên nhóm               [Chỉ Admin]
6. Chuyển quyền Admin         [Chỉ Admin]
7. Rời nhóm
8. Xóa nhóm                   [Chỉ Admin]
0. Quay lại
```

Kiểm tra quyền được thực hiện **cả ở Client (UI) và Server (endpoint)**. Nếu thành viên thường cố gọi action Admin, Client in:
```
[-] TỪ CHỐI TRUY CẬP: Chỉ Quản trị viên (Admin) mới có quyền thực hiện hành động này.
```
Server cũng trả về `403 Access Denied` độc lập với Client.

**Luồng thêm thành viên (Admin):**

```
Admin nhập username người mới
→ Tải chứng chỉ X.509 người mới từ Auth Server /registry/<username>
→ Trích xuất Public Key RSA của người mới
→ Tải wrapped_gmk của bản thân từ File Server
→ Giải mã GMK bằng Private Key RSA cục bộ
→ Mã hóa GMK bằng RSA-OAEP với Public Key người mới → wrapped_gmk_mới
→ Gửi lên File Server (action: "invite") kèm wrapped_gmk_mới
→ Người mới thấy lời mời ở mục "Lời mời vào nhóm" (status: 'pending')
```

**Luồng chấp nhận lời mời:**

```
Thành viên mới vào mục "Lời mời vào nhóm"
→ Chọn nhóm → xác nhận Y
→ Nhập tên hiển thị trong nhóm
→ Tải wrapped_gmk từ Server → giải mã bằng Private Key cục bộ → GMK vào RAM
→ Gửi action "accept_invite" + display_name lên File Server (status: 'active')
```

**Xử lý rời nhóm:**

- Admin cố rời khi còn thành viên khác → Server trả về: `You are the admin. Transfer admin rights before leaving. Use option 6.`
- Admin là thành viên duy nhất → rời sẽ tự động xóa nhóm

### 6.8 Audit Log

Tất cả giao dịch được ghi vào `file_server/logs/audit_log.txt`:

```
[2026-05-20T10:00:00.000000] [GROUP] User 'alice' created group 'Nhom_KMA'.
[2026-05-20T10:05:12.000000] [FILE] User 'alice' uploaded file 'baocao.pdf' to target 'Nhom_KMA'.
[2026-05-20T10:10:00.000000] [FILE_DOWNLOAD] User 'bob' requested encrypted blob for file_id 'a1b2...'.
[2026-05-20T10:15:00.000000] [FILE_PURGE] Tệp tin 'a1b2...' đã bị xóa khỏi hệ thống bởi 'bob'.
```

---

## 7. Cấu trúc thư mục dự án

```
MHUD_CK_File_Sharing/
│
├── docker-compose.yml          # Khai báo 4 container: postgres_db, ca_server, auth_server, file_server
├── requirements.txt            # Flask, cryptography, PyJWT, psycopg2, pandas, openpyxl
├── clean.py                    # Công cụ reset toàn bộ hệ thống về trạng thái sạch ban đầu
├── export_db.py                # Công cụ xuất toàn bộ database PostgreSQL ra file Excel
│
├── ca_server/
│   ├── Dockerfile
│   ├── ca_server.py            # Flask app: /issue_cert, /crl
│   ├── root_ca/                # root_key.pem, root_cert.pem (tự động sinh lần đầu boot)
│   └── intermediate_ca/        # int_key.pem, int_cert.pem, crl.pem (tự động sinh lần đầu boot)
│
├── auth_server/
│   ├── Dockerfile
│   ├── auth_server.py          # Flask app: /register, /login, /public_key, /registry/<username>
│   ├── auth_priv_key.pem       # Private Key RSA-2048 ký JWT Session Ticket (tự động sinh)
│   ├── auth_pub_key.pem        # Public Key tương ứng (chia sẻ với File Server)
│   └── nonce_store.db          # File chốt volume Docker (dữ liệu nonce lưu trong PostgreSQL)
│
├── file_server/
│   ├── Dockerfile
│   ├── file_server.py          # Flask app: upload, download, delete, group management
│   ├── storage/                # Blob mã hóa (đặt tên theo file_id UUID)
│   ├── logs/
│   │   └── audit_log.txt       # Nhật ký kiểm toán toàn hệ thống
│   └── database/               # Thư mục dự phòng (dữ liệu thực lưu trong PostgreSQL)
│
└── client/
    ├── client.py               # Ứng dụng terminal Python đầy đủ tính năng
    └── client_data/
        └── <username>/         # Thư mục cô lập cho từng người dùng
            ├── <username>_priv.pem     # Private Key RSA-2048 (không bao giờ rời khỏi máy)
            └── <username>_cert.pem     # Chuỗi chứng chỉ X.509 (User → Intermediate → Root)
```

---

## 8. Công cụ tiện ích

### `clean.py` — Reset hệ thống

Đưa toàn bộ hệ thống về trạng thái sạch hoàn toàn: xóa tất cả khóa CA, chứng chỉ, tệp mã hóa, log, và dữ liệu client.

```bash
python clean.py
```

Kịch bản thực hiện theo thứ tự:

1. `docker-compose down` — hạ toàn bộ container và giải phóng quyền đọc/ghi file
2. Xóa nội dung `ca_server/root_ca/` và `ca_server/intermediate_ca/`
3. Tái tạo file trống `auth_server/auth_priv_key.pem` và `auth_server/auth_pub_key.pem`
4. Xóa nội dung `file_server/storage/`, `file_server/logs/`, `file_server/database/`
5. Xóa nội dung `client/client_data/`

Sau khi reset, chạy lại `docker-compose up --build` để hệ thống tự khởi tạo PKI mới.

### `export_db.py` — Xuất database ra Excel

Xuất toàn bộ nội dung các bảng trong PostgreSQL ra file `database_export.xlsx` (mỗi bảng một Sheet). Dữ liệu nhị phân như khóa mã hóa được tự động chuyển thành chuỗi HEX cho dễ đọc.

```bash
# Yêu cầu: container postgres_db đang chạy (docker-compose up)
python export_db.py
```

---

## 9. Bảng tổng hợp yêu cầu đã đạt

| Mức | Yêu cầu | Hiện thực trong mã nguồn |
|---|---|---|
| **Cơ bản** | Mã hóa lai ghép AES + RSA | FSK (AES-256-GCM) mã hóa nội dung tệp; RSA-OAEP bọc FSK (cá nhân) hoặc AES-GCM bọc FSK (nhóm) |
| **Cơ bản** | Vòng đời khóa (tạo, phân phối) | GMK sinh ngẫu nhiên khi tạo nhóm; bọc RSA-OAEP riêng cho từng thành viên; Admin thực hiện xoay vòng thủ công khi xóa thành viên |
| **Cơ bản** | Chống Replay Attack (Nonce + Timestamp) | Mọi request gắn `X-Nonce` (128-bit hex) + `X-Timestamp` (ISO 8601); server kiểm tra TTL 5 phút và bảng `nonces` PostgreSQL bền vững |
| **Cơ bản** | Xác thực nguồn gốc khóa công khai | Khóa công khai phân phối qua chứng chỉ X.509 từ hệ thống PKI; Auth Server đóng vai trò Public Key Registry |
| **Tốt** | Tách biệt Master Key và Session Key | GMK là Master Key tồn tại xuyên suốt vòng đời nhóm; FSK là Session Key per-file; FSK luôn được bọc dưới GMK |
| **Tốt** | Kiểm soát truy cập theo danh tính | Admin-only (thêm/xóa thành viên, đổi tên nhóm, chuyển quyền, xóa nhóm) được kiểm tra độc lập ở cả Client lẫn Server |
| **Tốt** | X.509, CRL, bảo vệ MITM | Chuỗi chứng chỉ hai tầng (Root → Intermediate → User); CRL kiểm tra tại mỗi lần đăng nhập; Public Key phân phối qua Auth Server Registry |
| **Nâng cao** | 3+ Docker container | 4 container: `ca_server` (PKI), `auth_server` (KDC/SSO), `file_server` (Resource), `postgres_db` (Database) |
| **Nâng cao** | PKI với chuỗi chứng chỉ | Root CA (RSA-4096, tự ký) → Intermediate CA (RSA-4096) → User Cert (RSA-2048, hiệu lực 1 năm) |
| **Nâng cao** | SSO / Kerberos-like Ticketing | Mật khẩu nhập một lần tại Auth Server; JWT RS256 (hiệu lực 2 giờ) dùng cho mọi request đến File Server; File Server không cần liên hệ Auth Server |
| **Nâng cao** | Audit Log | `./logs/audit_log.txt` ghi đầy đủ sự kiện: `FILE` (upload), `FILE_DOWNLOAD`, `FILE_PURGE`, `GROUP` (tạo nhóm) |
