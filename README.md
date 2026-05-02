# easynet

easynet 是一个配置驱动的网络隧道与访问转发项目。它可以按客户端或服务端模式运行，并通过规则决定流量是直连、代理还是拒绝。

本文档只保留长期稳定的使用信息。具体实现细节请以代码和配置文件为准。

## 运行要求

- Rust 2021 edition 工具链
- 可用的 TUN/TAP 或对应系统网络设备支持
- 运行网络设备相关功能时，通常需要管理员或 root 权限
- Windows、Linux、macOS 的网络设备配置方式不同，部署前请先在目标环境验证

## 构建

开发构建：

```bash
cargo build
```

发布构建：

```bash
cargo build --release
```

生成的程序名称为 `easynet`。在 Windows 下通常为 `target/release/easynet.exe`。

## 配置

默认配置文件路径：

```text
config/easynet.yaml
```

程序启动时会读取该文件。主要配置分为以下几类：

- `runtime`：运行模式与日志级别
- `client`：客户端连接服务端所需配置
- `server`：服务端监听、隧道设备和证书配置
- `rules`：流量处理规则
- `transparent_proxy`：透明代理相关配置

## 运行

启动前先确认 `config/easynet.yaml` 中的 `runtime.mode`。

客户端模式：

```yaml
runtime:
  mode: client
```

服务端模式：

```yaml
runtime:
  mode: server
```

运行：

```bash
cargo run
```

或运行发布版本：

```bash
./target/release/easynet
```

Windows PowerShell：

```powershell
.\target\release\easynet.exe
```

## 规则

规则写在 `rules` 下，每条规则一行：

```yaml
rules:
  - DST_ADDR,1.1.1.1/32,direct
  - DST_PORT,80,direct
  - PROTO,tcp,proxy
  - MATCH,direct
```

规则格式：

```text
字段,值,动作
```

`MATCH` 是全匹配规则：

```text
MATCH,动作
```

支持的字段：

| 字段 | 说明 |
| --- | --- |
| `SRC-IP-CIDR` / `SRC_ADDR` | 源 IP 段 |
| `DST-IP-CIDR` / `DST_ADDR` | 目标 IP 段 |
| `SRC-PORT` | 源端口 |
| `DST-PORT` | 目标端口 |
| `PROTO` | 协议，支持 `tcp`、`udp`、`icmp` |
| `MATCH` | 全匹配 |

支持的动作：

| 动作 | 说明 |
| --- | --- |
| `direct` | 直连 |
| `proxy` | 代理 |
| `reject` | 拒绝 |

规则按配置顺序匹配。建议把更具体的规则写在前面，把 `MATCH` 放在最后作为兜底规则。

## 常用命令

检查编译：

```bash
cargo check
```

运行测试：

```bash
cargo test
```

格式化代码：

```bash
cargo fmt
```

查看详细日志：

```bash
RUST_LOG=debug cargo run
```

Windows PowerShell：

```powershell
$env:RUST_LOG="debug"
cargo run
```

## 注意事项

- 修改配置后需要重新启动程序。
- 网络设备、路由和防火墙配置依赖操作系统环境，请在部署环境单独验证。
- 证书、密钥、令牌等敏感信息不要提交到公开仓库。
- `config/client_state.yaml` 用于保存客户端运行状态，通常不需要手动修改。
- 本项目仍在演进中，生产环境使用前请完成安全、稳定性和兼容性验证。
