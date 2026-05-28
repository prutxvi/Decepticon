# syntax=docker/dockerfile:1
# Skillogy server image.
#
# Lean: only the decepticon-core types, the skillogy module, and the
# REST+gRPC stack. No langgraph, no langchain, no sandbox dependencies.

FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY packages/decepticon/decepticon/skillogy ./decepticon/skillogy
COPY packages/decepticon/decepticon/skillogy/proto ./decepticon/skillogy/proto

# Ship the canonical in-tree skill corpus. Operators can mount a
# different /app/skills volume to override.
COPY packages/decepticon/decepticon/skills ./skills

COPY packages/decepticon/__init__.py ./decepticon/__init__.py 2>/dev/null || RUN touch ./decepticon/__init__.py

RUN pip install --no-cache-dir \
    "fastapi>=0.115.0" \
    "uvicorn[standard]>=0.30.0" \
    "pydantic>=2.0.0" \
    "pyyaml>=6.0.0" \
    "grpcio>=1.66.0"

ENV SKILLOGY_SKILLS_ROOT=/app/skills
ENV SKILLOGY_REST_PORT=9100
ENV SKILLOGY_GRPC_PORT=50051

EXPOSE 9100 50051

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9100/v1/health')" || exit 1

CMD ["python", "-m", "decepticon.skillogy"]
