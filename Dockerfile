# ---- 构建阶段 ----
FROM python:3.12-slim

# 换源加速（可选，国内服务器可保留）
# RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 先装依赖缓存层
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 再拷贝源码
COPY . .

EXPOSE 8000

# 启动时初始化数据库并运行
CMD ["python", "app.py"]
