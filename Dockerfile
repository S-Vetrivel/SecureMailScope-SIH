FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY dashboard/package*.json ./
RUN npm install
COPY dashboard/ .
RUN npm run build

FROM golang:1.25-bookworm AS backend-builder
RUN apt-get update && apt-get install -y libpcap-dev gcc g++ make && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ .
RUN CGO_ENABLED=1 GOOS=linux go build -o server ./cmd/server

FROM python:3.11-slim AS final
RUN apt-get update && apt-get install -y tshark iproute2 curl nginx && rm -rf /var/lib/apt/lists/*

# Configure Nginx
RUN rm /etc/nginx/sites-enabled/default
COPY nginx.conf /etc/nginx/sites-enabled/securemailscope.conf

WORKDIR /app

# Copy AI engine and install requirements
COPY ai_engine/requirements.txt /app/ai_engine/
RUN pip install --no-cache-dir -r /app/ai_engine/requirements.txt
COPY ai_engine/ /app/ai_engine/

# Copy Go backend
COPY --from=backend-builder /app/server /app/server

# Copy React frontend
COPY --from=frontend-builder /app/dist /app/dashboard/dist

# Create necessary directories
RUN mkdir -p /data/database /data/captures /data/reports /data/uploads /data/captures/live

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 6000

ENTRYPOINT ["/app/entrypoint.sh"]
