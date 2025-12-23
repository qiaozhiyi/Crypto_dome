# comms.py
import socket
import struct
import time

try:
    from .encrypto import MLKEMEncryption
except ImportError:
    from encrypto import MLKEMEncryption


class SecureComm:
    def __init__(self, host, port, is_server=True):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.encryption = MLKEMEncryption()

    def send_message(self, message: bytes, aad: bytes = b""):
        """
        向接收方发送加密消息
        参数：
            message (bytes): 要发送的消息
            aad (bytes): 附加认证数据（可选）
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            server_public_key = self._recv_blob(s)
            self.encryption.public_key = server_public_key

            kem_ciphertext, salt, nonce, data_ciphertext = self.encryption.encrypt_data(
                message,
                aad,
            )
            self._send_blob(s, kem_ciphertext)
            self._send_blob(s, salt)
            self._send_blob(s, nonce)
            self._send_blob(s, aad)
            self._send_blob(s, data_ciphertext)

    def receive_message(self):
        """
        接收加密的消息并解密
        返回：解密后的数据
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(1)
            conn, addr = s.accept()
            with conn:
                self._send_blob(conn, self.encryption.public_key)
                kem_ciphertext = self._recv_blob(conn)
                salt = self._recv_blob(conn)
                nonce = self._recv_blob(conn)
                aad = self._recv_blob(conn)
                data_ciphertext = self._recv_blob(conn)
                return self.encryption.decrypt_data(
                    kem_ciphertext,
                    salt,
                    nonce,
                    data_ciphertext,
                    aad,
                )

    @staticmethod
    def _send_blob(sock, blob: bytes):
        sock.sendall(struct.pack("!I", len(blob)))
        if blob:
            sock.sendall(blob)

    @staticmethod
    def _recv_exact(sock, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("Socket closed before receiving expected data.")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _recv_blob(self, sock) -> bytes:
        raw_len = self._recv_exact(sock, 4)
        (length,) = struct.unpack("!I", raw_len)
        if length == 0:
            return b""
        return self._recv_exact(sock, length)


# 示例：如何使用通信模块发送和接收加密消息
def client():
    comm = SecureComm("127.0.0.1", 5555, is_server=False)
    message = b"Hello, this is a secure message from client!"
    comm.send_message(message)


def server():
    comm = SecureComm("127.0.0.1", 5555, is_server=True)
    decrypted_message = comm.receive_message()
    print(f"Received decrypted message: {decrypted_message.decode()}")


if __name__ == "__main__":
    # 在不同的线程中运行客户端和服务器
    import threading

    # 启动服务器线程
    server_thread = threading.Thread(target=server)
    server_thread.start()

    # 启动客户端线程
    time.sleep(0.2)
    client_thread = threading.Thread(target=client)
    client_thread.start()

    # 等待线程完成
    client_thread.join()
    server_thread.join()
