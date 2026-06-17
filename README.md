# requests2

基于百度直连代理的 HTTP 客户端封装，通过自定义 `HTTPAdapter` 实现 CONNECT 隧道代理。

## 特性

- 🔒 **HTTPS 隧道代理** — 复写 `requests.HTTPAdapter.send()`，通过原生 socket 建立 CONNECT 隧道
- 🔄 **自动重试** — CONNECT 隧道建立失败时内置最多 3 次重试
- 🛡️ **DNS 防护** — 自动跳过被劫持的 `198.18.x.x` 段 IP
- 📦 **解压支持** — 支持 gzip / deflate / brotli 自动解压
- 🧩 **chunked 解码** — 完整支持 HTTP chunked 传输编码
- 🧵 **接口兼容** — 类方法接口与 `requests` 库保持一致

## 安装

```bash
pip install requests brotli
```

> `brotli` 为可选依赖，未安装时回退到 gzip/deflate 解压。

## 快速开始

```python
from requests2 import http_request

# GET 请求
r = http_request.get("https://www.ipplus360.com/getIP")
print(r.text)

# POST JSON 请求
r = http_request.post("https://httpbin.org/post", json={"hello": "world"})
print(r.json())

# 任意 HTTP 方法
r = http_request.request("PUT", "https://example.com/data", data=b"...")
```

## 配置

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `UPSTREAM` | `("cloudnproxy.n.shifen.com", 443)` | 上游代理地址 |
| `CONNECT_TIMEOUT` | `10` | 连接超时（秒） |
| `READ_TIMEOUT` | `30` | 读取超时（秒） |
| `MAX_TUNNEL_RETRIES` | `3` | CONNECT 隧道最大重试次数 |

## 工作原理

```
客户端 ──TCP──▶ 百度代理 ──CONNECT 隧道──▶ 目标 HTTPS 服务器
                        (TLS 包装)
```

1. DNS 解析百度代理 IP，过滤被劫持的地址段
2. 通过代理建立 CONNECT 隧道，完成 TLS 握手
3. 在 TLS 加密通道中发送纯 HTTP 请求
4. 接收并解析原始 HTTP 响应（含 chunked 解码、压缩解压）
5. 构造标准 `requests.Response` 对象返回

## 异常体系

| 异常 | 说明 |
|------|------|
| `ProxyConnectionError` | 代理连接相关总异常 |
| `TunnelError` | CONNECT 隧道建立失败 |
| `ResponseParseError` | HTTP 响应解析失败 |

## 注意事项

- 当前仅支持 **HTTPS** 请求（通过 `https://` 前缀判断）
- 每次请求建立新的 CONNECT 隧道，请求结束后立即关闭
- 默认**不跟随重定向**（`allow_redirects=False`）
