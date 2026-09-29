# 迷你 FTPS 服务器/客户端

> [English version](README.md)

> [Russian version](README_RU.md)

一个自包含的迷你 FTPS 服务器/客户端项目（FTP over TLS/SSL），使用 C/C++ 编写，基于 **crypery** 库（TLS 1.2/1.3）。服务器支持身份验证、被动模式、数据传输通道加密以及通过 JSON 文件进行配置。

## 项目特点

- **自研 TLS 实现** - 无需外部加密库（OpenSSL、GnuTLS 等）
- **支持 TLS 1.2 和 TLS 1.3** - 自动检测版本或强制指定
- **JSON 配置** - 所有服务器参数均在 `config.json` 文件中设置
- **被动模式（PASV/EPSV）** - 用于数据传输的被动端口范围
- **用户名和密码身份验证** - 可配置的凭据
- **control 和 data 通道加密** - PROT P（Private）和 PROT C（Clear）
- **完整的 FTP 命令集** - LIST、MLSD、RETR、STOR、MKD、RMD、DELE、RNFR/RNTO、CWD、CDUP、PWD、SIZE 等
- **路径沙箱** - 防止通过 `..` 逃逸出根目录
- **跨平台** - 支持 Windows（MSVC/GCC）和 Linux/Unix
- **自签名证书** - 当 `localhost.crt`/`localhost.key` 缺失时自动生成

## 配置参数

配置从 `config.json` 文件加载。所有参数都有默认值。

```json
{
    "port": 2121,
    "root": "ftps_root",
    "passive_port_start": 50000,
    "passive_port_end": 50100,
    "control_timeout": 60,
    "data_timeout": 30,
    "pasv_timeout": 10,
    "username": "ftpuser",
    "password": "ftppass",
    "cert_file": "localhost.crt",
    "key_file": "localhost.key",
    "use_tls": true,
    "tls_version": 0,
    "log_output": 0
}
```

### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|----------|-----|-------------|----------|
| `port` | 数字 | 2121 | 服务器监听传入 FTP 连接的端口（1-65535） |
| `root` | 字符串 | "ftps_root" | FTPS 服务器的根目录。所有客户端路径均相对于此目录 |
| `passive_port_start` | 数字 | 50000 | 用于数据传输的被动连接范围的起始端口 |
| `passive_port_end` | 数字 | 50100 | 被动连接范围的结束端口（不包含）。服务器在此范围内循环分配端口 |
| `control_timeout` | 数字 | 60 | control 连接的超时时间（秒）。超过此时间的非活动连接将被断开 |
| `data_timeout` | 数字 | 30 | 文件传输期间 data 连接的超时时间（秒） |
| `pasv_timeout` | 数字 | 10 | 建立被动 data 连接的超时时间（秒）。客户端必须在此时间内连接到被动端口 |
| `username` | 字符串 | "ftpuser" | 用于在 FTPS 服务器上身份验证的用户名 |
| `password` | 字符串 | "ftppass" | 用于在 FTPS 服务器上身份验证的密码 |
| `cert_file` | 字符串 | "localhost.crt" | 服务器证书文件名（PEM 格式） |
| `key_file` | 字符串 | "localhost.key" | 服务器私钥文件名（PEM 格式） |
| `use_tls` | 布尔值 | true | 启用/禁用 TLS 加密。当为 `false` 时，服务器以无加密的普通 FTP 模式运行 |
| `tls_version` | 数字 | 0 | TLS 版本：`0`（自动）、`1`（强制 TLS 1.2）、`2`（强制 TLS 1.3） |
| `log_output` | 数字 | 0 | 日志输出：`0`（控制台和文件）、`1`（仅控制台）、`2`（仅文件 ftps_server.log） |

## 日志记录

服务器支持将事件记录到控制台和/或 `ftps_server.log` 文件。

### 日志参数

- 日志以 `[YYYY-MM-DD HH:MM:SS]` 格式的时间戳写入
- 数字日志级别：`0`（DEBUG）、`1`（INFO）、`2`（WARN）、`3`（ERROR）
- 配置中的 `log_output` 参数：`0`（both）、`1`（console）、`2`（file）
- 日志文件 `ftps_server.log` 创建在当前工作目录中
- 在日志系统初始化之前，消息输出到 stdout/stderr

## 命令行

```
ftps_server.exe [config_path] [root_override]
```

| 参数 | 说明 |
|----------|----------|
| `config_path` | JSON 配置文件的路径。如果是数字 - 解释为端口（覆盖 config.json 中的 `port`） |
| `root_override` | 覆盖 config.json 中的根目录 |

示例：
```bash
ftps_server.exe                        # 使用默认的 config.json
ftps_server.exe my_config.json         # 使用自定义配置文件
ftps_server.exe 21                     # 使用端口 21，默认配置
ftps_server.exe 21 /var/ftp            # 端口 21，根目录 /var/ftp
```

## 构建

```batch
build_ftps.bat
```

## 使用证书

服务器尝试从 `localhost.crt` 和 `localhost.key` 文件（PEM 格式）加载证书和密钥。如果文件未找到或无效，服务器将自动生成自签名证书。

要创建自己的证书：

```bash
openssl req -x509 -newkey rsa:2048 -keyout localhost.key -out localhost.crt -days 365 -nodes -subj "/CN=ftps server"
```

## 支持的 FTP 命令

| 命令 | 说明 |
|---------|----------|
| `LIST`、`MLSD` | 列出目录中的文件 |
| `RETR` | 获取文件（下载） |
| `STOR` | 上传文件（上传） |
| `MKD` | 创建目录 |
| `RMD` | 删除目录 |
| `DELE` | 删除文件 |
| `RNFR` / `RNTO` | 重命名/移动 |
| `CWD` / `CDUP` | 切换/返回父目录 |
| `PWD` | 当前目录 |
| `SIZE` | 文件大小 |
| `PASV` / `EPSV` | 被动模式 |
| `TYPE` | 传输类型（A/I） |
| `PROT` | 保护级别（C/P） |
| `PBSZ` | 保护缓冲区大小 |
| `AUTH TLS` | 开始 TLS 握手 |
| `FEAT` | 支持的功能 |
| `OPTS` | 命令选项 |
| `SYST` | 系统信息 |
| `NOOP` | 连接检查 |
| `QUIT` | 终止连接 |
| `REST` | 重启传输 |
| `MLST` | 文件/目录元数据 |
| `SITE CHMOD` | 更改文件权限 |

## License

GNU AGPL v3 (Affero GPL)
