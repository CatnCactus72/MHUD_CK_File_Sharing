FROM python:3.9-slim

WORKDIR /app

# Cài đặt thư viện
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép mã nguồn vào container
COPY auth_server/auth_server.py .

EXPOSE 5002

CMD ["python", "auth_server.py"]