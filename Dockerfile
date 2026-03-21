# 1. 使用官方的、轻量级的 Python 镜像作为基础
FROM python:3.10-slim

# 2. 设置容器内的工作目录
WORKDIR /app

# 3. 设置环境变量：防止 Python 将 .pyc 文件写入光盘，以及确保 stdout/stderr 不被缓冲
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# 4. 利用 Docker 缓存层：先复制 requirements.txt 并安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 复制 Flask 项目的全部代码到容器内
COPY . .

# 6. 声明 Flask 将运行的端口（与主路由器的 nginx-proxy 转发端口一致）
EXPOSE 5000

# 7. 【极其关键】：使用 Gunicorn 启动生产级服务器。
# 假设你的项目入口是 'run.py'，并且 Flask 实例在代码中被命名为 'app'。
CMD ["gunicorn", "--workers=4", "--bind=0.0.0.0:5000", "run:app"]
