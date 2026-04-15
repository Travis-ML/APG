FROM python:3.12-slim AS base

WORKDIR /app

# Install dependencies first for layer caching
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy application code
COPY apg/ apg/
COPY config/ config/

# Create runtime directories
RUN mkdir -p /etc/apg/policies /var/log/apg /var/apg/observe

# Copy default config and policies
COPY config/apg.yaml /etc/apg/apg.yaml
COPY config/policies/ /etc/apg/policies/
COPY config/tool_mappings.yaml /etc/apg/tool_mappings.yaml

ENV APG_CONFIG=/etc/apg/apg.yaml

EXPOSE 9001

HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9001/v1/health')" || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "apg.server:build_app", "--factory", "--host", "0.0.0.0", "--port", "9001"]
