# easynet

基于 Rust 开发的网络代理工具，支持客户端/服务端架构，通过 TUN 虚拟网卡实现网络流量劫持与规则路由。

## 特性

- **多协议传输**：支持 TCP、UDP、WebSocket (WS/WSS) 四种传输协议
- **灵活的路由规则**：支持 10 种匹配条件，可组合使用
- **GEOIP 分流**：基于 MaxMind GeoLite2 数据库按国家/地区分流
- **透明代理**：客户端内置 smoltcp 协议栈，Direct 流量本地直连
- **会话保持**：支持断线重连，客户端重连后保持原有虚拟 IP
- **Token 认证**：服务端可配置 Token 防止未授权连接
- **心跳保活**：3 秒间隔的 keepalive 机制，实时计算延迟
- **跨平台**：支持 Windows、Linux、macOS

## 架构

```
┌──────────┐         ┌──────────┐
│  客户端   │◄───────►│  服务端   │
│  (TUN)   │  TCP/   │  (TUN)   │
│          │  UDP/   │          │
│  ┌─────┐ │  WS/WSS │  ┌─────┐ │
│  │规则  │ │         │  │规则  │ │
│  │引擎  │ │         │  │引擎  │ │
│  └─────┘ │         │  └─────┘ │
│  ┌─────┐ │         │          │
│  │透明  │ │         │          │
│  │代理  │─┼──►直连   │          │
│  └─────┘ │         │          │
└──────────┘         └──────────┘
```

- **客户端**：创建 TUN 虚拟网卡，根据规则将流量通过传输层发送到服务端（Proxy），或经由透明代理直接访问目标（Direct）
- **服务端**：接收客户端隧道流量，通过 TUN 网卡转发到目标网络

## 快速开始

### 前置条件

1. 安装 [Rust](https://www.rust-lang.org/) 工具链
2. 准备 TLS 证书（用于 WS/WSS 模式），或使用自签名证书

### 编译

```bash
git clone <repo-url> easynet
cd easynet
cargo build --release
```

### 生成自签名证书（可选）

```bash
mkdir -p certs
# 生成 CA 证书
openssl genrsa -out certs/ca-key.pem 2048
openssl req -new -x509 -days 3650 -key certs/ca-key.pem -out certs/ca-cert.pem -subj "/CN=easynet-ca"

# 生成服务端证书
openssl genrsa -out certs/server-key.pem 2048
openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/CN=easynet-server"
openssl x509 -req -days 3650 -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/server-cert.pem
```

### 下载 GeoIP 数据库（可选）

如需使用 GEOIP 规则，从 [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/) 下载 GeoLite2-Country.mmdb，放入 `rules/geoip/` 目录。

> 注意：MaxMind 现已要求注册账号获取免费许可密钥。

## 配置说明

配置文件位于 `config/easynet.yaml`，首次运行时会自动生成默认配置。

### 完整配置项

```yaml
# === 运行配置 ===
runtime:
  mode: client              # 运行模式：client | server
  log_level: info           # 日志级别：trace | debug | info | warn | error

# === 客户端配置 ===
client:
  transport_type: ws        # 传输协议：tcp | udp | ws | wss
  server_addr: 192.168.6.111:12345  # 服务端地址
  ca_cert_path: certs/ca-cert.pem   # CA 证书路径（WS/WSS 模式需要）
  token: admin              # 认证 Token

# === 服务端配置 ===
server:
  transport_type: ws        # 传输协议：tcp | udp | ws | wss
  bind_addr: 0.0.0.0:12345 # 监听地址
  tun_name: tun1            # TUN 网卡名称
  tun_addr: 10.0.0.1        # TUN 网卡 IP
  tun_netmask: 255.255.255.0 # TUN 子网掩码
  tun_destination: 10.0.0.0 # TUN 目标网段
  tun_dns_servers: 114.114.114.114,8.8.8.8  # DNS 服务器（逗号分隔或列表）
  tun_mtu: 1400             # TUN MTU
  cert_path: certs/server-cert.pem  # 服务端证书路径
  key_path: certs/server-key.pem    # 服务端私钥路径
  token: admin              # 认证 Token（为空则不验证）

# === 规则列表 ===
rules:
  - DST-IP-CIDR,10.0.0.0/8,proxy   # 私有 IP 走代理
  - GEOIP,CN,direct                 # 中国 IP 直连
  - MATCH,proxy                     # 默认走代理

# === 规则集配置 ===
rule_sets:
  geoip_path: rules/geoip/GeoLite2-Country.mmdb  # GeoIP 数据库路径

# === 透明代理配置（客户端） ===
transparent_proxy:
  interface: "以太网"       # 物理网卡名称
  smoltcp_addr: 10.0.0.2   # smoltcp 协议栈地址
  smoltcp_netmask: 255.255.255.0
  smoltcp_gateway: 10.0.0.1
  upstream_server: null     # 上游代理 IP（可选）
```

### 运行模式

| 配置项 | 值 | 说明 |
| ------ | ------ | ---- |
| `runtime.mode` | `client` | 客户端模式，创建 TUN 网卡，连接服务端 |
| `runtime.mode` | `server` | 服务端模式，监听端口，等待客户端连接 |

### 传输协议

| 协议 | 适用场景 | 需要证书 |
| ---- | -------- | -------- |
| `tcp` | 低延迟场景，可靠传输 | 否 |
| `udp` | 高吞吐场景，弱网环境 | 否 |
| `ws` | 伪装 HTTP 流量，穿透防火墙 | 否 |
| `wss` | 加密传输，防嗅探 | 是 |

## 规则系统

### 规则格式

每条规则采用逗号分隔的紧凑格式：

```
<匹配类型>,<匹配值>,<动作>
```

- `MATCH` 类型无匹配值，格式为 `MATCH,<动作>`

### 匹配类型

| 类型 | 格式示例 | 说明 |
| ---- | -------- | ---- |
| `MATCH` | `MATCH,proxy` | 匹配所有流量，通常作为兜底规则 |
| `SRC-IP-CIDR` | `SRC-IP-CIDR,192.168.1.0/24,direct` | 匹配源 IP 网段 |
| `DST-IP-CIDR` | `DST-IP-CIDR,10.0.0.0/8,proxy` | 匹配目标 IP 网段 |
| `SRC-PORT` | `SRC-PORT,80,reject` | 匹配源端口，支持范围 `8000-9000` |
| `DST-PORT` | `DST-PORT,443,proxy` | 匹配目标端口，支持范围 `8000-9000` |
| `PROTO` | `PROTO,icmp,reject` | 匹配协议：tcp / udp / icmp |
| `DOMAIN` | `DOMAIN,example.com,direct` | 精确匹配域名 |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX,google.com,proxy` | 匹配域名后缀（含所有子域名） |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,youtube,proxy` | 匹配域名关键字 |
| `GEOIP` | `GEOIP,CN,direct` | 按国家/地区代码匹配 |

### 动作

| 动作 | 说明 |
| ---- | ---- |
| `direct` | 直连，流量不经隧道，由客户端本地发出 |
| `proxy` | 代理，流量通过隧道转发到服务端 |
| `reject` / `drop` | 拒绝，直接丢弃数据包 |

### 匹配优先级

规则按配置顺序从上到下依次匹配，命中即停止。**规则顺序很关键**，建议将精确规则放前面，宽泛规则放后面，最后以 `MATCH` 作为默认策略。

### GEOIP 特殊代码

| 代码 | 说明 |
| ---- | ---- |
| `PRIVATE` | 匹配私有 IP（含 10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、127.0.0.0/8、169.254.0.0/16、224.0.0.0/4、100.64.0.0/10 CGNAT 等） |
| `CN`、`US` 等 | ISO 3166-1 两位国家代码，需配合 GeoIP 数据库使用 |

### 规则示例

```yaml
rules:
  # 局域网流量直连
  - DST-IP-CIDR,10.0.0.0/8,direct
  - DST-IP-CIDR,172.16.0.0/12,direct
  - DST-IP-CIDR,192.168.0.0/16,direct
  # 中国 IP 直连
  - GEOIP,CN,direct
  # 禁止 ICMP
  - PROTO,icmp,reject
  # 特定域名走代理
  - DOMAIN-SUFFIX,google.com,proxy
  - DOMAIN-SUFFIX,twitter.com,proxy
  # 22 端口直接拒绝
  - DST-PORT,22,reject
  # 其余全部走代理
  - MATCH,proxy
```

## 透明代理

客户端在 Direct 模式下使用内置的 [smoltcp](https://github.com/smoltcp-rs/smoltcp) TCP/IP 协议栈进行本地直连，实现零拷贝的网络转发。

### 配置

```yaml
transparent_proxy:
  interface: "以太网"       # 本机物理网卡名称（Windows 在网络连接中查看）
  smoltcp_addr: 10.0.0.2   # 协议栈内部地址（通常无需修改）
  smoltcp_netmask: 255.255.255.0
  smoltcp_gateway: 10.0.0.1
  upstream_server: null     # 上游代理 IP，null 表示直连
```

### 工作原理

```
应用流量 → TUN 网卡 → 规则引擎
                         ├── Proxy → 传输层 → 服务端
                         └── Direct → smoltcp 协议栈 → 物理网卡 → 目标服务器
```

## 运行

```bash
# 直接运行
.\target\release\easynet.exe     # Windows
./target/release/easynet         # Linux / macOS
```

首次运行会自动在 `config/` 目录生成默认配置文件，修改配置后重新启动即可。

## 项目结构

```
easynet/
├── config/
│   └── easynet.yaml          # 主配置文件
├── certs/                    # TLS 证书目录
├── rules/
│   └── geoip/
│       └── GeoLite2-Country.mmdb  # GeoIP 数据库
├── src/
│   ├── main.rs               # 入口
│   ├── config.rs             # 配置解析
│   ├── client.rs             # 客户端逻辑
│   ├── server.rs             # 服务端逻辑（含会话管理）
│   ├── tun_device.rs         # TUN 网卡管理
│   ├── codec/                # 消息编解码（protobuf）
│   ├── transport/            # 传输层实现（TCP/UDP/WS）
│   ├── transparent_proxy/    # 透明代理（smoltcp）
│   │   ├── tcp_proxy.rs
│   │   ├── udp_proxy.rs
│   │   ├── icmp_proxy.rs
│   │   └── filter.rs
│   └── rules/                # 规则引擎库
│       ├── engine.rs         # 规则引擎
│       ├── matcher.rs        # 规则匹配器
│       ├── rule.rs           # 规则定义
│       ├── geoip.rs          # GeoIP 匹配
│       └── context.rs        # 数据包上下文
└── Cargo.toml
```

## 许可

MIT
