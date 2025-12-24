# 使用 Python 3.12 的官方镜像作为基础镜像
FROM python:3.12

# 设置工作目录为 /app
WORKDIR /app

# 将整个项目复制到容器的 /app 目录
COPY . /app

# 给所有文件授予读写执行权限
RUN chmod -R 777 /app

# 安装依赖项
RUN pip install --no-cache-dir -r requirements.txt

# 设置容器启动时的默认命令，运行 cli.py
CMD ["python", "cli/cli.py"]

