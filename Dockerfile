FROM python:3.9-slim

# Install OpenSSL and necessary tools
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
COPY ./templates/ ./templates/
COPY app.py .
COPY cert-manager.sh .

# Ensure directories exist
RUN mkdir -p certs rootCA

EXPOSE 5000

CMD ["python", "app.py"]