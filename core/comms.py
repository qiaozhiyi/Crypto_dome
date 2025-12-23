# comms.py
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable, Optional

DEFAULT_MAX_BLOB_SIZE = 16 * 1024 * 1024  # 16 MiB
DEFAULT_BACKLOG = 128


def _new_default_encryption(*, is_server: bool):
    try:
        from .encrypto import MLKEMEncryption
    except ImportError:
        from encrypto import MLKEMEncryption
    return MLKEMEncryption(generate_keypair=is_server)


class SecureCommProtocol:
    public_key: bytes

    def encrypt_data(
        self,
        data: bytes,
        aad: bytes = b"",
        *,
        public_key: Optional[bytes] = None,
    ):
        raise NotImplementedError

    def decrypt_data(
        self,
        kem_ciphertext: bytes,
        salt: bytes,
        nonce: bytes,
        data_ciphertext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True)
class SecureCommConfig:
    backlog: int = DEFAULT_BACKLOG
    max_blob_size: int = DEFAULT_MAX_BLOB_SIZE
    connect_timeout: float = 5.0
    io_timeout: float = 10.0
    accept_timeout: float = 1.0


class SecureComm:
    def __init__(
        self,
        host: str,
        port: int,
        is_server: bool = True,
        *,
        encryption: Optional[SecureCommProtocol] = None,
        config: SecureCommConfig = SecureCommConfig(),
    ):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.config = config
        self.encryption: SecureCommProtocol = (
            encryption if encryption is not None else _new_default_encryption(is_server=is_server)
        )

    def send_message(self, message: bytes, aad: bytes = b""):
        """
        向接收方发送加密消息
        参数：
            message (bytes): 要发送的消息
            aad (bytes): 附加认证数据（可选）
        """
        with socket.create_connection(
            (self.host, self.port),
            timeout=self.config.connect_timeout,
        ) as s:
            s.settimeout(self.config.io_timeout)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            server_public_key = self._recv_blob(s, max_size=self.config.max_blob_size)
            kem_ciphertext, salt, nonce, data_ciphertext = self.encryption.encrypt_data(
                message,
                aad,
                public_key=server_public_key,
            )
            self._send_blob(s, kem_ciphertext)
            self._send_blob(s, salt)
            self._send_blob(s, nonce)
            self._send_blob(s, aad)
            self._send_blob(s, data_ciphertext)

    def receive_message(self):
        """
        接收单条加密消息并解密（一次性服务器）。
        高并发/高压场景建议使用 SecureCommServer.serve_forever。
        """
        with SecureCommServer(
            self.host,
            self.port,
            encryption=self.encryption,
            config=self.config,
        ) as server:
            return server.serve_once()

    @staticmethod
    def _send_blob(sock, blob: bytes):
        if len(blob) > 0xFFFFFFFF:
            raise ValueError("Blob too large for 4-byte length prefix.")

        sock.sendall(struct.pack("!I", len(blob)))
        if blob:
            sock.sendall(blob)

    @staticmethod
    def _recv_exact(sock, size: int) -> bytes:
        buf = bytearray(size)
        view = memoryview(buf)
        received = 0
        while received < size:
            n = sock.recv_into(view[received:], size - received)
            if n == 0:
                raise ConnectionError("Socket closed before receiving expected data.")
            received += n
        return bytes(buf)

    @staticmethod
    def _recv_blob(sock, *, max_size: int) -> bytes:
        raw_len = SecureComm._recv_exact(sock, 4)
        (length,) = struct.unpack("!I", raw_len)
        if length > max_size:
            raise ValueError(f"Incoming blob too large: {length} > {max_size}")
        if length == 0:
            return b""
        return SecureComm._recv_exact(sock, length)


class SecureCommServer:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        encryption: Optional[SecureCommProtocol] = None,
        config: SecureCommConfig = SecureCommConfig(),
    ):
        self.host = host
        self.port = port
        self.config = config
        self.encryption: SecureCommProtocol = (
            encryption if encryption is not None else _new_default_encryption(is_server=True)
        )
        self._sock: Optional[socket.socket] = None

    @property
    def bound_port(self) -> int:
        if self._sock is None:
            return self.port
        return self._sock.getsockname()[1]

    def start(self) -> None:
        if self._sock is not None:
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
        s.bind((self.host, self.port))
        s.listen(self.config.backlog)
        s.settimeout(self.config.accept_timeout)
        self._sock = s

    def __enter__(self) -> "SecureCommServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self._sock.close()
        finally:
            self._sock = None

    def serve_once(self) -> bytes:
        self.start()
        assert self._sock is not None

        conn, addr = self._sock.accept()
        with conn:
            conn.settimeout(self.config.io_timeout)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return self._handle_connection(conn)

    def serve_forever(
        self,
        handler: Callable[[bytes, tuple[str, int]], None],
        *,
        stop_event=None,
        max_workers: int = 64,
    ) -> None:
        self.start()
        assert self._sock is not None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while stop_event is None or not stop_event.is_set():
                try:
                    conn, addr = self._sock.accept()
                except socket.timeout:
                    continue

                conn.settimeout(self.config.io_timeout)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                executor.submit(self._handle_and_dispatch, conn, addr, handler)

    def _handle_and_dispatch(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        handler: Callable[[bytes, tuple[str, int]], None],
    ) -> None:
        with conn:
            try:
                message = self._handle_connection(conn)
            except Exception:
                return
            handler(message, addr)

    def _handle_connection(self, conn: socket.socket) -> bytes:
        SecureComm._send_blob(conn, self.encryption.public_key)
        kem_ciphertext = SecureComm._recv_blob(conn, max_size=self.config.max_blob_size)
        salt = SecureComm._recv_blob(conn, max_size=self.config.max_blob_size)
        nonce = SecureComm._recv_blob(conn, max_size=self.config.max_blob_size)
        aad = SecureComm._recv_blob(conn, max_size=self.config.max_blob_size)
        data_ciphertext = SecureComm._recv_blob(conn, max_size=self.config.max_blob_size)
        return self.encryption.decrypt_data(
            kem_ciphertext,
            salt,
            nonce,
            data_ciphertext,
            aad,
        )


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
