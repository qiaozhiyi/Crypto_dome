# comms.py
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import secrets
import socket
import ssl
import struct
import time
from dataclasses import dataclass
from typing import Callable, Optional

DEFAULT_MAX_BLOB_SIZE = 16 * 1024 * 1024  # 16 MiB
DEFAULT_BACKLOG = 128

#校验倒入加密函数
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


@dataclass(frozen=True)
class TLSConfig:
    enabled: bool = False
    ca_file: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    server_hostname: Optional[str] = None
    check_hostname: bool = True
    require_client_cert: bool = False
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    def _build_client_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_file)
        ctx.minimum_version = self.minimum_version
        ctx.check_hostname = self.check_hostname
        if self.cert_file is not None:
            ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def _build_server_context(self) -> ssl.SSLContext:
        if self.cert_file is None:
            raise ValueError("TLS server requires cert_file.")
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = self.minimum_version
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        if self.require_client_cert:
            if self.ca_file is None:
                raise ValueError("TLS client cert verification requires ca_file.")
            ctx.load_verify_locations(cafile=self.ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


@dataclass(frozen=True)
class AuthConfig:
    shared_key: bytes | str
    client_id: str = "client"
    allowed_client_ids: Optional[frozenset[str]] = None
    max_time_skew_sec: int = 60

    def __post_init__(self) -> None:
        key = self.shared_key.encode("utf-8") if isinstance(self.shared_key, str) else self.shared_key
        if len(key) < 16:
            raise ValueError("auth.shared_key too short; use >= 16 bytes.")
        object.__setattr__(self, "shared_key", key)
        if self.allowed_client_ids is not None and not isinstance(self.allowed_client_ids, frozenset):
            object.__setattr__(self, "allowed_client_ids", frozenset(self.allowed_client_ids))


_AUTH_CHALLENGE_MAGIC = b"SC_AUTH_CHAL1"
_AUTH_RESPONSE_MAGIC = b"SC_AUTH_RES1"
_AUTH_OK_MAGIC = b"SC_AUTH_OK1"
_AUTH_SERVER_NONCE_LEN = 32
_AUTH_CLIENT_NONCE_LEN = 32
_AUTH_PK_HASH_LEN = 32


class SecureComm:
    def __init__(
        self,
        host: str,
        port: int,
        is_server: bool = True,
        *,
        encryption: Optional[SecureCommProtocol] = None,
        config: SecureCommConfig = SecureCommConfig(),
        tls: Optional[TLSConfig] = None,
        auth: Optional[AuthConfig] = None,
    ):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.config = config
        self.tls = tls
        self.auth = auth
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
        raw = socket.create_connection(
            (self.host, self.port),
            timeout=self.config.connect_timeout,
        )
        raw.settimeout(self.config.io_timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            conn = self._wrap_client_socket(raw)
        except Exception:
            raw.close()
            raise

        with conn:
            server_public_key = self._recv_blob(conn, max_size=self.config.max_blob_size)
            session_id = b""
            if self.auth is not None:
                session_id = self._auth_client(
                    conn,
                    self.auth,
                    server_public_key=server_public_key,
                    max_size=self.config.max_blob_size,
                )
            kem_ciphertext, salt, nonce, data_ciphertext = self.encryption.encrypt_data(
                message,
                session_id + aad,
                public_key=server_public_key,
            )
            self._send_blob(conn, kem_ciphertext)
            self._send_blob(conn, salt)
            self._send_blob(conn, nonce)
            self._send_blob(conn, aad)
            self._send_blob(conn, data_ciphertext)

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
            tls=self.tls,
            auth=self.auth,
        ) as server:
            return server.serve_once()

    def _wrap_client_socket(self, sock: socket.socket) -> socket.socket:
        if self.tls is None or not self.tls.enabled:
            return sock
        ctx = self.tls._build_client_context()
        server_hostname = self.tls.server_hostname
        if self.tls.check_hostname and server_hostname is None:
            server_hostname = self.host
        tls_sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        tls_sock.settimeout(self.config.io_timeout)
        return tls_sock

    @staticmethod
    def _hmac_sha256(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def _auth_client(
        conn: socket.socket,
        auth: AuthConfig,
        *,
        server_public_key: bytes,
        max_size: int,
    ) -> bytes:
        server_pk_hash = hashlib.sha256(server_public_key).digest()
        challenge = SecureComm._recv_blob(conn, max_size=max_size)
        if not challenge.startswith(_AUTH_CHALLENGE_MAGIC):
            raise PermissionError("auth handshake failed: missing challenge magic")
        off = len(_AUTH_CHALLENGE_MAGIC)
        if len(challenge) != off + 8 + _AUTH_SERVER_NONCE_LEN + _AUTH_PK_HASH_LEN:
            raise PermissionError("auth handshake failed: bad challenge length")

        server_ts = struct.unpack("!Q", challenge[off : off + 8])[0]
        server_nonce = challenge[off + 8 : off + 8 + _AUTH_SERVER_NONCE_LEN]
        pk_hash = challenge[off + 8 + _AUTH_SERVER_NONCE_LEN :]
        if not hmac.compare_digest(pk_hash, server_pk_hash):
            raise PermissionError("auth handshake failed: server public key mismatch")
        now = int(time.time())
        if abs(now - int(server_ts)) > auth.max_time_skew_sec:
            raise PermissionError("auth handshake failed: server time skew too large")

        client_ts = now
        client_nonce = secrets.token_bytes(_AUTH_CLIENT_NONCE_LEN)
        client_id_bytes = auth.client_id.encode("utf-8")
        if len(client_id_bytes) > 255:
            raise ValueError("client_id too long")

        mac_input = (
            _AUTH_RESPONSE_MAGIC
            + struct.pack("!Q", server_ts)
            + server_nonce
            + server_pk_hash
            + struct.pack("!Q", client_ts)
            + client_nonce
            + struct.pack("!B", len(client_id_bytes))
            + client_id_bytes
        )
        mac = SecureComm._hmac_sha256(auth.shared_key, mac_input)
        response = mac_input + mac
        SecureComm._send_blob(conn, response)

        ok = SecureComm._recv_blob(conn, max_size=max_size)
        if not ok.startswith(_AUTH_OK_MAGIC) or len(ok) != len(_AUTH_OK_MAGIC) + 32:
            raise PermissionError("auth handshake failed: bad server ok")
        expected_ok = SecureComm._hmac_sha256(
            auth.shared_key,
            _AUTH_OK_MAGIC + server_nonce + client_nonce + server_pk_hash,
        )
        if not hmac.compare_digest(ok[len(_AUTH_OK_MAGIC) :], expected_ok):
            raise PermissionError("auth handshake failed: server proof invalid")

        return hashlib.sha256(
            b"SC_SESSION1" + server_nonce + client_nonce + server_pk_hash + client_id_bytes
        ).digest()

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
        tls: Optional[TLSConfig] = None,
        auth: Optional[AuthConfig] = None,
    ):
        self.host = host
        self.port = port
        self.config = config
        self.tls = tls
        self.auth = auth
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
        conn.settimeout(self.config.io_timeout)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            tls_conn = self._wrap_server_socket(conn)
        except Exception:
            conn.close()
            raise

        with tls_conn:
            return self._handle_connection(tls_conn)

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
        try:
            tls_conn = self._wrap_server_socket(conn)
        except Exception:
            conn.close()
            return

        with tls_conn:
            try:
                message = self._handle_connection(tls_conn)
            except Exception:
                return
            handler(message, addr)

    def _wrap_server_socket(self, sock: socket.socket) -> socket.socket:
        if self.tls is None or not self.tls.enabled:
            return sock
        ctx = self.tls._build_server_context()
        tls_sock = ctx.wrap_socket(sock, server_side=True)
        tls_sock.settimeout(self.config.io_timeout)
        return tls_sock

    @staticmethod
    def _auth_server(
        conn: socket.socket,
        auth: AuthConfig,
        *,
        server_public_key: bytes,
        max_size: int,
    ) -> tuple[bytes, bytes, bytes]:
        server_nonce = secrets.token_bytes(_AUTH_SERVER_NONCE_LEN)
        server_ts = int(time.time())
        server_pk_hash = hashlib.sha256(server_public_key).digest()
        challenge = _AUTH_CHALLENGE_MAGIC + struct.pack("!Q", server_ts) + server_nonce + server_pk_hash
        SecureComm._send_blob(conn, challenge)

        resp = SecureComm._recv_blob(conn, max_size=max_size)
        if not resp.startswith(_AUTH_RESPONSE_MAGIC):
            raise PermissionError("auth handshake failed: missing response magic")
        off = len(_AUTH_RESPONSE_MAGIC)
        min_len = (
            off
            + 8
            + _AUTH_SERVER_NONCE_LEN
            + _AUTH_PK_HASH_LEN
            + 8
            + _AUTH_CLIENT_NONCE_LEN
            + 1
            + 32
        )
        if len(resp) < min_len:
            raise PermissionError("auth handshake failed: response too short")

        parsed_server_ts = struct.unpack("!Q", resp[off : off + 8])[0]
        if int(parsed_server_ts) != int(server_ts):
            raise PermissionError("auth handshake failed: challenge mismatch")
        parsed_server_nonce = resp[off + 8 : off + 8 + _AUTH_SERVER_NONCE_LEN]
        if not hmac.compare_digest(parsed_server_nonce, server_nonce):
            raise PermissionError("auth handshake failed: nonce mismatch")

        parsed_pk_hash = resp[
            off + 8 + _AUTH_SERVER_NONCE_LEN : off + 8 + _AUTH_SERVER_NONCE_LEN + _AUTH_PK_HASH_LEN
        ]
        if not hmac.compare_digest(parsed_pk_hash, server_pk_hash):
            raise PermissionError("auth handshake failed: server public key mismatch")

        p = off + 8 + _AUTH_SERVER_NONCE_LEN + _AUTH_PK_HASH_LEN
        client_ts = struct.unpack("!Q", resp[p : p + 8])[0]
        p += 8
        client_nonce = resp[p : p + _AUTH_CLIENT_NONCE_LEN]
        p += _AUTH_CLIENT_NONCE_LEN
        client_id_len = resp[p]
        p += 1
        client_id_bytes = resp[p : p + client_id_len]
        p += client_id_len
        mac = resp[p:]
        if len(mac) != 32:
            raise PermissionError("auth handshake failed: bad mac length")

        now = int(time.time())
        if abs(now - int(client_ts)) > auth.max_time_skew_sec:
            raise PermissionError("auth handshake failed: client time skew too large")

        client_id = client_id_bytes.decode("utf-8", errors="strict")
        if auth.allowed_client_ids is not None and client_id not in auth.allowed_client_ids:
            raise PermissionError("auth handshake failed: client_id not allowed")

        expected_mac = SecureComm._hmac_sha256(auth.shared_key, resp[: p])
        if not hmac.compare_digest(mac, expected_mac):
            raise PermissionError("auth handshake failed: bad mac")

        ok = _AUTH_OK_MAGIC + SecureComm._hmac_sha256(
            auth.shared_key,
            _AUTH_OK_MAGIC + server_nonce + client_nonce + server_pk_hash,
        )
        SecureComm._send_blob(conn, ok)

        session_id = hashlib.sha256(
            b"SC_SESSION1" + server_nonce + client_nonce + server_pk_hash + client_id_bytes
        ).digest()
        return session_id, server_nonce, client_nonce

    def _handle_connection(self, conn: socket.socket) -> bytes:
        session_id = b""
        SecureComm._send_blob(conn, self.encryption.public_key)
        if self.auth is not None:
            session_id, _, _ = self._auth_server(
                conn,
                self.auth,
                server_public_key=self.encryption.public_key,
                max_size=self.config.max_blob_size,
            )
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
            session_id + aad,
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
