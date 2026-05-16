FROM python:3.9-slim

WORKDIR /app

# Cài đặt thư viện
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY file_server/file_server.py .

# Khởi tạo các thư mục lưu trữ persistent
RUN mkdir -p database storage logs

EXPOSE 5003

CMD ["python", "file_server.py"]