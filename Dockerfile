# Minimal pinned runtime (reproducibility requirement, design Part J.1).
FROM python:3.11-slim

# Determinism control: fixed hash seed (design Part J.1 / PROJECT_RULES.md Setup).
ENV PYTHONHASHSEED=0

# Pinned uv — same version family used to produce uv.lock.
RUN pip install --no-cache-dir uv==0.10.6

WORKDIR /app

# Locked environment first (layer caching), then the source tree.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen

COPY . .

ENV PATH="/app/.venv/bin:${PATH}"
CMD ["pytest", "-q"]
