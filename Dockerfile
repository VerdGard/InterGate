# InterGate 一键容器镜像
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 INTERGATE_DATA_DIR=/app/data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data
EXPOSE 51234 51235
# 默认单进程启动网关+Web; 可用环境变量覆盖(见 README)
CMD ["python3", "main.py"]
