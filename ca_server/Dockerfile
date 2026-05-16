FROM python:3.9-slim

WORKDIR /app

# COPY file requirements.txt từ thư mục gốc (do build context đã đổi ra thư mục gốc)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# COPY file mã nguồn chính của CA Server
COPY ca_server/ca_server.py .

# Tạo sẵn các thư mục chứa khóa PKI theo đúng đặc tả kỹ thuật (mục 10)
RUN mkdir -p root_ca intermediate_ca

EXPOSE 5001

# Chạy file server duy nhất
CMD ["python", "ca_server.py"]