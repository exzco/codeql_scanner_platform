




#### postgresql 启动
```bash
docker run -d \
  --name postgres-codeql \
  -p 5432:5432 \
  -e POSTGRES_USER=codeql \
  -e POSTGRES_PASSWORD=codeql123 \
  -e POSTGRES_DB=codeql_platform \
  -v postgres_data:/var/lib/postgresql \
  postgres:latest
```

#### redis 启动
```bash
docker run -d \
  --name redis-codeql \
  -p 6379:6379 \
  -v redis_data:/data \
  redis:latest
```

#### minio 启动
```bash
docker pull minio/minio
docker run -d \
  -p 9000:9000 \
  -p 9001:9001 \
  --name minio-server \
  -e "MINIO_ROOT_USER=minioadmin" \
  -e "MINIO_ROOT_PASSWORD=minioadmin123" \
  -v /mnt/data:/data \
  minio/minio server /data --console-address ":9001"
```