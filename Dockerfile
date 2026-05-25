# BBAT Docker Image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    nmap \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (optional but recommended)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip -o nuclei.zip && \
    unzip nuclei.zip -d /usr/local/bin/ && \
    rm nuclei.zip && \
    chmod +x /usr/local/bin/nuclei

# Install Chrome dependencies for screenshots
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers for screenshot module
RUN python -m playwright install chromium || true

COPY . .

# Create output directory
RUN mkdir -p output

VOLUME ["/app/output"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
