# 安全的远程管理与加密通信框架

该项目是一个基于 **python** 开发的 **安全的远程管理工具**，旨在为合法的远程访问、运维、监控以及数据加密提供一个高效、合规、安全的解决方案。通过强加密保护通信，确保数据传输的机密性和完整性，并提供完整的审计与权限控制功能。

## 项目目标

1. **安全的远程管理代理**：
    - 提供强加密的远程管理通信。
    - 支持基于角色的权限控制（RBAC）。
    - 支持远程 Shell、文件传输和系统信息收集等功能。

2. **加密通信架构**：
    - 实现端到端加密，确保通信内容不会被窃听或篡改。
    - 支持 **后量子加密**
    
3. **审计与日志管理**：
    - 自动记录所有远程操作和事件。
    - 集中存储日志，支持日志分析与审计。

## 项目结构


``` text
C2-Framework/
├── core/                # 核心通信模块
│   ├── comms.py        # 网络通信（支持 TCP/UDP、HTTP 隧道）
│   ├── encryption.py   # 加密模块（量子加密、后量子加密）
│ 
├── modules/             # 后渗透模块
│   ├── reverse_shell.py   # 反向 Shell 控制
│   ├── file_transfer.py   # 文件上传/下载
│   ├── keylogger.py      # 键盘记录
│   ├── system_info.py    # 系统信息收集
│   └── password_crack.py # 密码破解
├── web/                 # Web 控制面板
│   ├── server.py        # Flask 后端
│   └── client.js        # 前端界面
├── payloads/            # Payload 模板与生成
│   ├── payload_win.py  # Windows 特定的 Payload
│   └── payload_linux.py # Linux 特定的 Payload
└── utils/               # 工具库
├── logger.py       # 日志管理
└── crypto.py       # 加密工具（包括量子加密模块）
```

## Docker 本地测试（通信/加密模块）

该仓库包含远程管理相关代码。为了在隔离环境里做“通信加密链路”自测，可以用 Docker 直接跑内置示例（不涉及外部网络目标）。

1) 构建镜像：

```bash
docker build -t crypto_dome:local .
```

2) 运行通信模块自测（同进程内起 server+client 发一条消息）：

```bash
docker run --rm crypto_dome:local
```

3) 运行加密模块自测（ML-KEM + AES-GCM 加解密演示）：

```bash
docker run --rm crypto_dome:local python core/encrypto.py
```
