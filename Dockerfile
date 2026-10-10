# Local sandbox pilot image. Prefer docker-compose (binds 127.0.0.1:8000).
# Aegotrax Risk Engine — simple pilot image
FROM python:3.11-slim

WORKDIR /app

# Install package
COPY pyproject.toml README.md ./
COPY aegotrax ./aegotrax

RUN pip install --no-cache-dir .

# Default policy lives in the image; can be overridden by volume
ENV AEGOTRAX_HOST=0.0.0.0
ENV AEGOTRAX_PORT=8000
ENV AEGOTRAX_AUDIT_LOG=/data/aegotrax_audit.log
ENV AEGOTRAX_POLICY_PATH=/data/policy.yaml

# Persist logs + policy outside the container
RUN mkdir -p /data && cp aegotrax/policy.yaml /data/policy.yaml

EXPOSE 8000

CMD ["python", "-m", "aegotrax.risk_engine"]
