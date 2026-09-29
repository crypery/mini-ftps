# Mini FTPS Server/Client

> [Russian version](README_RU.md)

> [China version](README_CN.md)

A self-contained mini FTPS server/client project (FTP over TLS/SSL) written in C/C++, built on the **crypery** library (TLS 1.2/1.3). The server supports authentication, passive mode, encryption of the data transfer channels, and configuration via a JSON file.

## Project Features

- **Own TLS implementation** - no external crypto libraries required (OpenSSL, GnuTLS, etc.)
- **TLS 1.2 and TLS 1.3 support** - automatic version detection or forced specification
- **JSON configuration** - all server parameters are set in the `config.json` file
- **Passive mode (PASV/EPSV)** - a range of passive ports for data transfer
- **Username and password authentication** - configurable credentials
- **Encryption of the control and data channels** - PROT P (Private) and PROT C (Clear)
- **Full set of FTP commands** - LIST, MLSD, RETR, STOR, MKD, RMD, DELE, RNFR/RNTO, CWD, CDUP, PWD, SIZE, etc.
- **Path sandbox** - protection against escaping the root directory via `..`
- **Cross-platform** - supports Windows (MSVC/GCC) and Linux/Unix
- **Self-signed certificate** - automatically generated when `localhost.crt`/`localhost.key` is missing

## Configuration Parameters

Configuration is loaded from the `config.json` file. All parameters have default values.

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

### Parameter Description

| Parameter | Type | Default | Description |
|----------|-----|-------------|----------|
| `port` | number | 2121 | Port on which the server listens for incoming FTP connections (1-65535) |
| `root` | string | "ftps_root" | Root directory of the FTPS server. All client paths are relative to this directory |
| `passive_port_start` | number | 50000 | Starting port of the passive connection range for data transfer |
| `passive_port_end` | number | 50100 | Ending port of the passive connection range (exclusive). The server cyclically distributes ports in this range |
| `control_timeout` | number | 60 | Timeout (seconds) for the control connection. Inactive connections beyond this are dropped |
| `data_timeout` | number | 30 | Timeout (seconds) for the data connection during file transfer |
| `pasv_timeout` | number | 10 | Timeout (seconds) for establishing the passive data connection. The client must connect to the passive port within this time |
| `username` | string | "ftpuser" | Username for authentication on the FTPS server |
| `password` | string | "ftppass" | Password for authentication on the FTPS server |
| `cert_file` | string | "localhost.crt" | Server certificate file name (PEM format) |
| `key_file` | string | "localhost.key" | Server private key file name (PEM format) |
| `use_tls` | boolean | true | Enable/disable TLS encryption. When `false`, the server runs in plain FTP mode without encryption |
| `tls_version` | number | 0 | TLS version: `0` (automatic), `1` (force TLS 1.2), `2` (force TLS 1.3) |
| `log_output` | number | 0 | Log output: `0` (both console and file), `1` (console only), `2` (file ftps_server.log only) |

## Logging

The server supports logging events to the console and/or to the `ftps_server.log` file.

### Logging Parameters

- Logs are written with timestamps in the format `[YYYY-MM-DD HH:MM:SS]`
- Numeric log levels: `0` (DEBUG), `1` (INFO), `2` (WARN), `3` (ERROR)
- The `log_output` parameter in the config: `0` (both), `1` (console), `2` (file)
- The log file `ftps_server.log` is created in the current working directory
- Before the logging system is initialized, messages are printed to stdout/stderr

## Command Line

```
ftps_server.exe [config_path] [root_override]
```

| Argument | Description |
|----------|----------|
| `config_path` | Path to the JSON configuration file. If a number - interpreted as a port (overrides `port` from config.json) |
| `root_override` | Override of the root directory from config.json |

Examples:
```bash
ftps_server.exe                        # Use the default config.json
ftps_server.exe my_config.json         # Use a custom configuration file
ftps_server.exe 21                     # Use port 21, default config
ftps_server.exe 21 /var/ftp            # Port 21, root /var/ftp
```

## Build

```batch
build_ftps.bat
```

## Using Certificates

The server tries to load the certificate and key from the `localhost.crt` and `localhost.key` files (PEM format). If the files are not found or are invalid, the server automatically generates a self-signed certificate.

To create your own certificates:

```bash
openssl req -x509 -newkey rsa:2048 -keyout localhost.key -out localhost.crt -days 365 -nodes -subj "/CN=ftps server"
```

## Supported FTP Commands

| Command | Description |
|---------|----------|
| `LIST`, `MLSD` | List files in a directory |
| `RETR` | Get a file (download) |
| `STOR` | Upload a file (upload) |
| `MKD` | Create a directory |
| `RMD` | Remove a directory |
| `DELE` | Delete a file |
| `RNFR` / `RNTO` | Rename/move |
| `CWD` / `CDUP` | Change/return to the parent directory |
| `PWD` | Current directory |
| `SIZE` | File size |
| `PASV` / `EPSV` | Passive mode |
| `TYPE` | Transfer type (A/I) |
| `PROT` | Protection level (C/P) |
| `PBSZ` | Protection buffer size |
| `AUTH TLS` | Start the TLS handshake |
| `FEAT` | Supported features |
| `OPTS` | Command options |
| `SYST` | System information |
| `NOOP` | Connection check |
| `QUIT` | Terminate the connection |
| `REST` | Restart transfer |
| `MLST` | File/directory metadata |
| `SITE CHMOD` | Change file permissions |

## License

GNU AGPL v3 (Affero GPL)
