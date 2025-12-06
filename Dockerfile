FROM python:3.9-slim

RUN apt-get update && apt-get install -y openssl net-tools && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN mkdir -p certs rootCA

COPY . .
COPY --chmod=0755 cert-manager.sh .

EXPOSE 5000

CMD ["python", "app.py"]
