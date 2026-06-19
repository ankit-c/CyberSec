FROM python:3.11-slim

WORKDIR /app

# System deps for lxml and cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libxml2-dev libxslt-dev libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idp.py .

EXPOSE 8080

CMD ["python", "idp.py"]
