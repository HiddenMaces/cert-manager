FROM python:3.9-slim

# Install OpenSSL and necessary tools
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure directories exist
RUN mkdir -p certs rootCA

EXPOSE 5000

CMD ["python", "app.py"]