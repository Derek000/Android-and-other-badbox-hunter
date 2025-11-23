FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update &&         apt-get install -y --no-install-recommends           nmap tcpdump tshark &&         rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

RUN python -m venv /venv &&         /venv/bin/pip install --no-cache-dir -r requirements.txt

ENV PATH="/venv/bin:${PATH}"

EXPOSE 8000

ENV BADBOX_HUNTER_DEFAULT_CIDRS="192.168.0.0/24"

CMD ["gunicorn", "-b", "0.0.0.0:8000", "web_app:app"]
