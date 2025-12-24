# Crypto_dome 接口文档（`core/comms.py` + `core/encrypto.py`）

本文档描述当前项目中“通信层 + 加密层”的对外接口、数据流与类之间的关系。

> 入口模块：`core/comms.py`  
> 加密实现：`core/encrypto.py`

---

## 1. 总览：分层与依赖关系

### 1.1 分层

- **传输层（Transport）**：TCP socket，可选 **TLS/SSL**（`ssl` 标准库）
- **认证/防篡改层（Auth/Binding）**：可选 **PSK-HMAC 握手**，导出 `session_id` 绑定到后续 AEAD 的 AAD
- **密钥封装与数据加密层（KEM+AEAD）**：ML-KEM（pqcrypto）+ AES-GCM（cryptography）

### 1.2 类/接口依赖图（文字版）

- `SecureComm`（客户端/一次性收消息封装）
  - 依赖：`SecureCommConfig`（超时/大小/队列等）
  - 依赖：`TLSConfig`（可选：TLS client context）
  - 依赖：`AuthConfig`（可选：PSK-HMAC 握手）
  - 依赖：`SecureCommProtocol`（加密后端的“接口形状”/duck-typing）
    - 默认实现来自 `_new_default_encryption()` → `MLKEMEncryption`（`core/encrypto.py`）
- `SecureCommServer`（服务器监听/并发处理）
  - 依赖：`SecureCommConfig`
  - 依赖：`TLSConfig`（可选：TLS server context）
  - 依赖：`AuthConfig`（可选：PSK-HMAC 握手）
  - 依赖：`SecureCommProtocol`（同上）

### 1.3 关键点：`SecureCommProtocol` 是“协议形状”而非强制继承

`SecureCommProtocol` 在 `core/comms.py` 里是一个基类（更像接口说明），但运行时并不强制要求加密类继承它；只要对象具备：

- 属性：`public_key: bytes`
- 方法：
  - `encrypt_data(data: bytes, aad: bytes=b"", public_key: Optional[bytes]=None) -> (kem_ciphertext, salt, nonce, data_ciphertext)`
  - `decrypt_data(kem_ciphertext, salt, nonce, data_ciphertext, aad=b"") -> bytes`

即可被 `SecureComm`/`SecureCommServer` 使用（duck typing）。

---

## 2. `core/encrypto.py`：加密层接口

### 2.1 `MLKEMEncryption`

文件：`core/encrypto.py`

用途：

- 服务器端生成 ML-KEM 密钥对（`public_key`/`private_key`）
- 客户端用服务器公钥做 KEM 封装，得到共享密钥，再用 AES-GCM 加密消息
- 服务器端用私钥做 KEM 解封装，再用 AES-GCM 解密消息

#### 2.1.1 构造函数

`MLKEMEncryption(generate_keypair=True, public_key=None, private_key=None)`

- `generate_keypair=True`：生成一对新的 ML-KEM 密钥（典型用于 server）
- `generate_keypair=False`：使用传入的 `public_key/private_key`（或允许只作为“客户端侧”仅用于封装）

约束：

- 如果传入 `public_key` 或 `private_key`，必须 `generate_keypair=False`

#### 2.1.2 关键属性

- `public_key: bytes | None`：ML-KEM 公钥
- `private_key: bytes | None`：ML-KEM 私钥（解密必需）

#### 2.1.3 关键方法

- `encapsulate_key(public_key: Optional[bytes]=None) -> (kem_ciphertext: bytes, shared_key: bytes)`
  - 输入：接收方（通常是 server）的 ML-KEM 公钥
  - 输出：KEM 密文 + 共享密钥
- `decapsulate_key(kem_ciphertext: bytes) -> shared_key: bytes`
  - 输入：KEM 密文
  - 输出：共享密钥（需要 `private_key`）
- `encrypt_data(data: bytes, aad: bytes=b"", public_key: Optional[bytes]=None) -> (kem_ciphertext, salt, nonce, data_ciphertext)`
  - 做法：KEM → HKDF → AES-GCM
  - 其中：
    - `salt`：HKDF 盐
    - `nonce`：AES-GCM nonce
    - `data_ciphertext`：密文（含 GCM tag）
    - `aad`：AES-GCM 的附加认证数据（不加密但完整性受保护）
- `decrypt_data(kem_ciphertext, salt, nonce, data_ciphertext, aad=b"") -> plaintext`

#### 2.1.4 与 `core/comms.py` 的关系

`SecureCommServer` 需要一个“有私钥”的加密对象用于解密（默认 `_new_default_encryption(is_server=True)` 会生成密钥对）。

客户端侧（`SecureComm(is_server=False)`）默认生成的 `MLKEMEncryption` 没有私钥也没有公钥，但没问题：它只用 `encrypt_data(..., public_key=server_public_key)` 做封装与对称加密。

---

## 3. `core/comms.py`：通信层接口

### 3.1 低层 framing：Blob 编码

`SecureComm._send_blob(sock, blob)` / `SecureComm._recv_blob(sock, max_size=...)`

- 帧格式：`[4字节大端长度][payload bytes...]`
- `max_blob_size`：防止超大包导致内存/DoS 风险

这个 framing 被用于：

- 服务器发送 `public_key`
- （可选）认证握手 challenge/response/ok
- 发送加密包：`kem_ciphertext`/`salt`/`nonce`/`aad`/`data_ciphertext`

### 3.2 配置类

#### 3.2.1 `SecureCommConfig`

文件：`core/comms.py`

字段（影响 socket 行为与防护）：

- `backlog`：listen backlog
- `max_blob_size`：单个 blob 最大字节数
- `connect_timeout`：客户端 connect 超时
- `io_timeout`：读写超时
- `accept_timeout`：服务端 accept 超时（用于循环 accept）

#### 3.2.2 `TLSConfig`

用途：在 TCP 之上启用 TLS。

主要字段：

- `enabled`：是否启用 TLS
- `ca_file`：CA 证书（客户端验证 server、或 server 验证 client）
- `cert_file` / `key_file`：本端证书与私钥（server 必填；client 在 mTLS 时需要）
- `server_hostname`：客户端 SNI/主机名校验用（默认用 `host`）
- `check_hostname`：客户端是否做 hostname 校验
- `require_client_cert`：server 是否要求并校验 client 证书（mTLS）
- `minimum_version`：TLS 最低版本（默认 TLSv1.2）

关系：

- `SecureComm` 调用 `TLSConfig._build_client_context()` 并 `wrap_socket(...)`
- `SecureCommServer` 调用 `TLSConfig._build_server_context()` 并 `wrap_socket(..., server_side=True)`

#### 3.2.3 `AuthConfig`

用途：在应用层做“身份验证 + 防篡改绑定”，并把认证结果绑定到 AEAD 的 AAD。

主要字段：

- `shared_key`：预共享密钥（PSK），用于 HMAC-SHA256
- `client_id`：客户端身份字符串（会参与签名/会话导出）
- `allowed_client_ids`：服务端可选白名单（不设置则不校验 client_id）
- `max_time_skew_sec`：允许的时间偏差（抗简单重放/时钟偏差）

关系：

- `SecureComm`/`SecureCommServer` 都可以配置 `auth=AuthConfig(...)`
- 启用后，会在每个连接的加密数据之前执行一次 HMAC 握手，导出 `session_id`
- 后续实际加密使用的 `aad` 变为：`session_id + user_aad`

### 3.3 核心接口类

#### 3.3.1 `SecureComm`

定位：高层便捷 API，主要用于客户端发消息；也提供一次性收消息封装。

构造：

`SecureComm(host, port, is_server=True, encryption=None, config=..., tls=None, auth=None)`

关键方法：

- `send_message(message: bytes, aad: bytes=b"") -> None`
  - 连接到 server（TCP）
  - 若 `tls.enabled`：先 TLS 握手（证书校验在 TLS 层完成）
  - 收到 server 的 `public_key`
  - 若配置了 `auth`：执行应用层 HMAC 握手，导出 `session_id`
  - 调用 `encryption.encrypt_data(message, aad=session_id+aad, public_key=server_public_key)`
  - 发送：`kem_ciphertext`、`salt`、`nonce`、`aad`（用户原始 aad）、`data_ciphertext`
- `receive_message() -> bytes`
  - 便捷封装：内部创建 `SecureCommServer(...).serve_once()`，只接一次连接

与 `SecureCommServer` 的关系：

- `SecureComm.receive_message()` 本质只是“临时启动一次性 server 并收一条消息”
- 高并发/常驻服务端应使用 `SecureCommServer.serve_forever(...)`

#### 3.3.2 `SecureCommServer`

定位：服务端监听 TCP；支持 `serve_once()`（一次）与 `serve_forever()`（并发）。

关键方法：

- `start()`：bind/listen/设置 accept timeout
- `serve_once() -> bytes`
  - accept 一个连接
  - 若启用 TLS：先把连接升级为 TLS
  - 调用 `_handle_connection()` 解密并返回明文
- `serve_forever(handler, stop_event=None, max_workers=64) -> None`
  - accept 循环 + 线程池并发
  - 每连接调用 `_handle_connection()`，再把明文交给 `handler(message, addr)`

### 3.4 连接级数据流（线协议）

以下顺序描述单连接内的数据帧（均为 blob framing：4 字节长度 + payload）。

#### 3.4.1 传输层

1. TCP 建连
2. （可选）TLS 握手与证书校验（启用 `TLSConfig.enabled` 时发生）

#### 3.4.2 应用层（`SecureCommServer._handle_connection` / `SecureComm.send_message`）

3. server → client：`server_public_key`
4. （可选）Auth 握手（启用 `AuthConfig` 时发生）
   - server → client：`challenge = MAGIC | server_ts | server_nonce | sha256(server_public_key)`
   - client → server：`response = MAGIC | server_ts | server_nonce | sha256(server_public_key) | client_ts | client_nonce | client_id_len | client_id | HMAC(PSK, response_body)`
   - server → client：`ok = MAGIC | HMAC(PSK, MAGIC | server_nonce | client_nonce | sha256(server_public_key))`
   - 双方导出 `session_id = sha256("SC_SESSION1" | server_nonce | client_nonce | sha256(server_public_key) | client_id)`
5. client → server：`kem_ciphertext`
6. client → server：`salt`
7. client → server：`nonce`
8. client → server：`aad`（用户原始 aad）
9. client → server：`data_ciphertext`（AES-GCM 密文）
10. server 解密时使用的 AAD：`session_id + aad`

安全含义（启用 auth 时）：

- 报文完整性：由 AES-GCM 保证（`aad` 与密文一起认证）
- 身份绑定：`session_id` 由 PSK-HMAC 握手导出，且与 `server_public_key` 哈希绑定；攻击者无法在不知 PSK 的情况下伪造/篡改
- 抗 MITM 替换公钥：握手内包含 `sha256(server_public_key)` 且被 HMAC 保护，server 端会拒绝任何与其真实公钥不一致的握手

---

## 4. 典型用法（示例）

> 导入方式提示：如果“项目根目录”在 `PYTHONPATH` 中，可以用 `from core.comms import ...`；如果你像测试一样把 `core/` 目录加入 `sys.path`，则使用 `import comms` / `import encrypto`。

### 4.1 仅使用 KEM+AEAD（无 TLS、无 Auth）

- 风险提示：没有认证 server 身份，存在 MITM 替换公钥的风险。

```python
from core.comms import SecureComm

SecureComm("127.0.0.1", 5555, is_server=False).send_message(b"hello")
```

### 4.2 启用 Auth（PSK-HMAC）做身份验证与防篡改绑定

```python
from core.comms import SecureComm, AuthConfig

auth = AuthConfig(shared_key=b"0123456789abcdef0123456789abcdef", client_id="client-A")
SecureComm("127.0.0.1", 5555, is_server=False, auth=auth).send_message(b"hello", aad=b"meta")
```

服务端（限制 client_id 白名单）：

```python
from core.comms import SecureCommServer, AuthConfig

auth = AuthConfig(
    shared_key=b"0123456789abcdef0123456789abcdef",
    allowed_client_ids=frozenset({"client-A"}),
)

with SecureCommServer("0.0.0.0", 5555, auth=auth) as s:
    msg = s.serve_once()
```

### 4.3 启用 TLS（推荐用于“证书级别”的 server 身份校验）

```python
from core.comms import SecureComm, TLSConfig

tls = TLSConfig(enabled=True, ca_file="ca.pem", check_hostname=True, server_hostname="example.com")
SecureComm("example.com", 5555, is_server=False, tls=tls).send_message(b"hello")
```

> 若需要 mTLS：服务端 `require_client_cert=True` 且配置 `ca_file`；客户端配置 `cert_file/key_file`。

---

## 5. 与测试的对应关系（可选参考）

文件：`tests/test_comms_concurrency.py`

- `DummyEncryption`：演示了“只要实现同样的方法签名/属性即可被 comms 使用”（duck typing）。
- `test_auth_handshake_*`：演示了 auth 握手的 challenge/response/ok 结构与验证路径。
