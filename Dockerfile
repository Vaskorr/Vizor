FROM node:22-bookworm AS web-build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:22-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIZOR_DATA_DIR=/data \
    NODE_ENV=production
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl nmap python3 python3-pip fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=web-build /app /app
RUN pip3 install --break-system-packages --no-cache-dir -r server/requirements.txt \
    && mkdir -p /data/scans \
    && chmod +x server/entrypoint.sh
EXPOSE 3000 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["bash", "server/entrypoint.sh"]
