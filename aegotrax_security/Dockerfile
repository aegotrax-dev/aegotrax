# AgentGuard Risk Engine — simple pilot image
FROM python:3.11-slim

WORKDIR /app

# Install package
COPY pyproject.toml README.md ./
COPY agentguard ./agentguard

RUN pip install --no-cache-dir .

# Default policy lives in the image; can be overridden by volume
ENV AGENTGUARD_HOST=0.0.0.0
ENV AGENTGUARD_PORT=8000
ENV AGENTGUARD_AUDIT_LOG=/data/agentguard_audit.log
ENV AGENTGUARD_POLICY_PATH=/data/policy.yaml

# Persist logs + policy outside the container
RUN mkdir -p /data && cp agentguard/policy.yaml /data/policy.yaml

EXPOSE 8000

CMD ["python", "-m", "agentguard.risk_engine"]
