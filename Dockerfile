FROM python:3.9-slim

RUN groupadd -g 1000 appgroup && \
    useradd -u 1000 -g appgroup -m appuser

RUN apt-get update && apt-get install -y openssl net-tools && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN mkdir -p certs rootCA && \
    chown -R appuser:appgroup certs rootCA

COPY --chown=appuser:appgroup . .
COPY --chown=appuser:appgroup --chmod=0755 cert-manager.sh .

USER 1000

EXPOSE 5000

CMD ["python", "app.py"]
