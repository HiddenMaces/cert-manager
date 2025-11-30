FROM python:3.9-slim

RUN groupadd -g 1000 appgroup && \
    useradd -u 1000 -g appgroup -m appuser

RUN apt-get update && apt-get install -y openssl net-tools && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
COPY ./templates/ ./templates/
COPY app.py .
COPY cert-manager.sh .

# Ensure directories exist
RUN mkdir -p certs rootCA
RUN chown -R appuser:appgroup /app
RUN chown +x ./cert-manager.sh

USER 1000

EXPOSE 5000

CMD ["python", "app.py"]