# 生产环境部署用的 Dockerfile

# 1. 使用官方的、轻量级的 Python 镜像作为基础
FROM python:3.12-slim

# 消除 debconf 交互警告
ENV DEBIAN_FRONTEND=noninteractive

# 2. 设置容器内的工作目录
WORKDIR /app

# 3. 设置环境变量：防止 Python 将 .pyc 文件写入光盘，以及确保 stdout/stderr 不被缓冲
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
# 添加这一行，它作为缓存“开关”
ARG CACHEBUST=1

# 自动安装依赖
# 注意：若仓库中无 requirements.txt，确保安装 Flask 和 Gunicorn 保证能跑起来
RUN if [ -f requirements.txt ]; then \
    pip install --no-cache-dir -r requirements.txt; \
    else \
    pip install --no-cache-dir flask gunicorn; \
    fi

# 确保gunicorn在PATH中
ENV PATH="/usr/local/bin:$PATH"

# 设置执行权限
RUN chmod +x /usr/local/bin/gunicorn

# 启动 Flask。注意：这里假设入口文件为 app.py
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
