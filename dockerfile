FROM node:20-alpine AS frontend-builder
WORKDIR /web

COPY web/package*.json ./
COPY web/ .
RUN npm config set registry https://registry.npmmirror.com/ && npm install
RUN npm run build


FROM golang:1.25-alpine AS backend-builder
WORKDIR /build/backend

ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o server main.go


FROM ubuntu:22.04 AS runner
WORKDIR /app

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates tzdata git && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=frontend-builder /web/dist /app/public
COPY --from=backend-builder /build/backend/configs /app/configs
COPY --from=backend-builder /build/backend/server /app/server
RUN chmod +x /app/server

EXPOSE 8080
CMD ["./server"]