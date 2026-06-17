"""
requests2 - 基于百度直连代理的 HTTP 客户端封装
用法：
    from requests2 import http_request
    r = http_request.get("https://example.com")
    r = http_request.post("https://example.com/api", json={"key": "value"})
"""
import gzip
import socket
import ssl
import time
from urllib.parse import urlparse
from typing import Optional, Dict, Tuple

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import brotli
except ImportError:
    brotli = None


# ==================== 配置（与 baidu_proxy.py 保持一致） ====================
UPSTREAM = ("cloudnproxy.n.shifen.com", 443)
PROXY_HEADERS = (
    "Host: ascdn.baidu.com\r\n"
    "Proxy-Connection: Keep-Alive\r\n"
    "X-T5-Auth: 1951164069\r\n"
    "User-Agent: okhttp/3.11.0 baiduboxapp/13.33.0.11\r\n"
)

# 连接超时（秒）
CONNECT_TIMEOUT = 10
# 读取超时（秒）—— 防止 socket.recv 无限阻塞
READ_TIMEOUT = 30
# CONNECT 隧道建立最大重试次数
MAX_TUNNEL_RETRIES = 3


# ==================== 自定义异常 ====================
class ProxyConnectionError(ConnectionError):
    """代理连接相关异常。"""
    pass


class TunnelError(ProxyConnectionError):
    """CONNECT 隧道建立失败。"""
    pass


class ResponseParseError(ProxyConnectionError):
    """HTTP 响应解析失败。"""
    pass


# ==================== DNS 解析（跳过本地劫持） ====================
def _resolve_proxy() -> str:
    """解析百度代理 IP，跳过被劫持的 198.18.x.x 段。

    Returns:
        真实代理 IP 地址。

    Raises:
        ProxyConnectionError: 无法解析代理域名。
    """
    try:
        addrs = socket.getaddrinfo(UPSTREAM[0], UPSTREAM[1])
        for addr in addrs:
            ip: str = addr[4][0]
            if not ip.startswith("198.18."):
                return ip
    except Exception:
        pass
    raise ProxyConnectionError(f"无法解析 {UPSTREAM[0]}")


# ==================== CONNECT 隧道建立 ====================
def _do_connect_tunnel(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> ssl.SSLSocket:
    """通过百度代理建立 CONNECT 隧道，返回已 TLS 握手的 socket。

    Args:
        host: 目标服务器主机名。
        port: 目标服务器端口。
        timeout: 连接超时（秒）。

    Returns:
        已 TLS 包装的 socket，可直接读写 HTTP 流量。

    Raises:
        TunnelError: 隧道建立失败。
    """
    last_err: Optional[str] = None

    for attempt in range(MAX_TUNNEL_RETRIES):
        try:
            proxy_ip = _resolve_proxy()
            sock = socket.create_connection((proxy_ip, UPSTREAM[1]), timeout=timeout)
            sock.settimeout(READ_TIMEOUT)

            connect_req = (
                f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"{PROXY_HEADERS}\r\n"
            )
            sock.sendall(connect_req.encode())

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk

            status_line = resp.split(b"\r\n")[0]
            if b"200" not in status_line:
                sock.close()
                last_err = f"代理隧道失败: {status_line.decode(errors='replace')}"
                if attempt < MAX_TUNNEL_RETRIES - 1:
                    time.sleep(1)
                    continue
                raise TunnelError(last_err)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(sock, server_hostname=host)

        except (TunnelError, ProxyConnectionError):
            # 不重试已知的隧道/代理异常，直接上抛
            raise
        except Exception as e:
            last_err = str(e)
            if attempt < MAX_TUNNEL_RETRIES - 1:
                time.sleep(1)
                continue
            raise ProxyConnectionError(f"连接代理失败: {last_err}") from e

    # 理论上不会走到这里，但保持安全
    raise TunnelError(last_err or "未知隧道错误")


# ==================== HTTP 响应解析 ====================
def _parse_http_response(raw: bytes, request_url: str,
                         original_request) -> requests.Response:
    """将原始 HTTP 响应字节解析为 requests.Response 对象。

    Args:
        raw: 原始 HTTP 响应字节。
        request_url: 请求 URL。
        original_request: 原始 requests.PreparedRequest 对象。

    Returns:
        构造好的 requests.Response 对象。

    Raises:
        ResponseParseError: 响应格式无法解析。
    """
    if b"\r\n\r\n" not in raw:
        raise ResponseParseError("代理返回空响应或格式异常")

    resp_hdr_bytes, resp_body = raw.split(b"\r\n\r\n", 1)

    # ---- 解析状态行 ----
    header_lines = resp_hdr_bytes.split(b"\r\n")
    status_line = header_lines[0].decode(errors="replace")
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 else 0
    reason = parts[2] if len(parts) >= 3 else ""

    # ---- 解析响应头 ----
    resp_headers: Dict[str, str] = {}
    for line in header_lines[1:]:
        if b":" in line:
            k, v = line.decode(errors="replace").split(":", 1)
            resp_headers[k.strip()] = v.strip()

    # ---- 处理 chunked 传输编码 ----
    if resp_headers.get("Transfer-Encoding", "").lower() == "chunked":
        resp_body = _decode_chunked(resp_body)

    # ---- 处理 Content-Length（非 chunked 情况） ----
    elif "Content-Length" in resp_headers:
        try:
            content_length = int(resp_headers["Content-Length"])
            resp_body = resp_body[:content_length]
        except ValueError:
            pass

    # ---- 解压缩 ----
    resp_body = _decompress_body(resp_body, resp_headers.get("Content-Encoding", ""))

    # ---- 构造 Response 对象 ----
    resp = requests.Response()
    resp.status_code = status_code
    resp.reason = reason
    resp.headers.update(resp_headers)
    resp._content = resp_body
    resp.encoding = requests.utils.get_encoding_from_headers(resp_headers)
    resp.url = request_url
    resp.request = original_request
    resp.connection = None
    resp.elapsed = None

    return resp


def _decode_chunked(data: bytes) -> bytes:
    """解码 chunked 传输编码。

    支持 chunk-extension（如 ``;name=value``），
    遇到最后一个 chunk（size=0）时停止，
    忽略 trailer 部分。

    Args:
        data: chunked 编码的原始 body。

    Returns:
        解码后的 body 字节。
    """
    result = bytearray()
    pos = 0
    data_len = len(data)

    while pos < data_len:
        # 找到 chunk-size 行结束
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            break

        chunk_head = data[pos:crlf]
        # 去掉 chunk-extension（分号后的部分）
        semicolon = chunk_head.find(b";")
        if semicolon != -1:
            chunk_head = chunk_head[:semicolon]

        try:
            chunk_size = int(chunk_head.strip(), 16)
        except ValueError:
            break

        if chunk_size == 0:
            # 最后一个 chunk，后面是 trailer + 最终 CRLF
            break

        chunk_start = crlf + 2
        chunk_end = chunk_start + chunk_size

        if chunk_end > data_len:
            # 数据不完整，截断
            result.extend(data[chunk_start:data_len])
            break

        result.extend(data[chunk_start:chunk_end])
        pos = chunk_end + 2  # 跳过 chunk-data 后的 CRLF

    return bytes(result)


def _decompress_body(data: bytes, content_encoding: str) -> bytes:
    """根据 Content-Encoding 解压响应体。

    Args:
        data: 压缩后的 body。
        content_encoding: Content-Encoding 头值。

    Returns:
        解压后的 body（无法解压时返回原数据）。
    """
    ce = content_encoding.lower().strip()

    if ce == "gzip":
        try:
            return gzip.decompress(data)
        except Exception:
            pass
    elif ce == "deflate":
        try:
            import zlib
            return zlib.decompress(data)
        except Exception:
            pass
    elif ce == "br" and brotli is not None:
        try:
            return brotli.decompress(data)
        except Exception:
            pass

    return data


# ==================== 自定义 Adapter ====================
class _ProxyAdapter(HTTPAdapter):
    """通过百度代理 CONNECT 隧道发送 HTTPS 请求。

    重写 HTTPAdapter.send()，用原生 socket 替代 urllib3 的
    连接池管理。每次请求建立新的 CONNECT 隧道，请求结束后关闭。
    """

    def send(self, request, **kwargs):
        parsed = urlparse(request.url)
        host: str = parsed.hostname or ""
        port: int = parsed.port or 443
        path: str = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        # 获取请求体
        body_data = request.body or b""
        if isinstance(body_data, str):
            body_data = body_data.encode()

        # 建立 CONNECT 隧道（内置重试）
        tls_sock = _do_connect_tunnel(host, port, CONNECT_TIMEOUT)

        try:
            # ---- 组装并发送 HTTP 请求 ----
            header_lines = [
                f"Host: {host}",
                "Connection: close",
                "User-Agent: curl/8.0",
                "Accept: */*",
            ]
            if body_data:
                header_lines.append(f"Content-Length: {len(body_data)}")
                if request.method in ("POST", "PUT", "PATCH"):
                    ct = request.headers.get("Content-Type", "application/octet-stream")
                    header_lines.append(f"Content-Type: {ct}")

            http_req = (
                f"{request.method} {path} HTTP/1.1\r\n"
                + "\r\n".join(header_lines)
                + "\r\n\r\n"
            )
            tls_sock.sendall(http_req.encode() + body_data)

            # ---- 读取完整响应 ----
            raw = _recv_all(tls_sock)

        finally:
            tls_sock.close()

        return _parse_http_response(raw, request.url, request)


# ==================== Socket 读取辅助 ====================
def _recv_all(sock: socket.socket, chunk_size: int = 4096) -> bytes:
    """从 socket 读取所有数据直到连接关闭，带超时保护。

    因为请求头设置了 ``Connection: close``，服务端会在发送完
    响应后关闭连接，所以读到空即停止。

    Args:
        sock: 已连接的 socket。
        chunk_size: 每次读取的块大小。

    Returns:
        接收到的全部字节。
    """
    raw = bytearray()
    while True:
        try:
            chunk = sock.recv(chunk_size)
            if not chunk:
                break
            raw.extend(chunk)
        except socket.timeout:
            # 超时后如果已有数据则返回，否则上抛
            if raw:
                break
            raise
        except OSError:
            break
    return bytes(raw)


# ==================== http_request 类 ====================
class http_request:
    """通过上游代理发送 HTTP 请求的封装类。

    提供类级别的 Session 单例，接口与 requests 库保持一致。

    Usage::

        r = http_request.get("https://example.com")
        r = http_request.post("https://example.com/api", json={"k": "v"})
        r = http_request.request("PUT", "https://example.com/data", data=b"...")
    """

    _session: Optional[requests.Session] = None

    @classmethod
    def _get_session(cls) -> requests.Session:
        if cls._session is None:
            cls._session = requests.Session()
            cls._session.mount("https://", _ProxyAdapter())
        return cls._session

    @classmethod
    def get(cls, url: str, **kwargs) -> requests.Response:
        """发送 GET 请求。"""
        kwargs.setdefault("allow_redirects", False)
        return cls._get_session().get(url, **kwargs)

    @classmethod
    def post(cls, url: str, **kwargs) -> requests.Response:
        """发送 POST 请求。"""
        kwargs.setdefault("allow_redirects", False)
        return cls._get_session().post(url, **kwargs)

    @classmethod
    def request(cls, method: str, url: str, **kwargs) -> requests.Response:
        """发送任意 HTTP 方法的请求。"""
        kwargs.setdefault("allow_redirects", False)
        return cls._get_session().request(method, url, **kwargs)


# ==================== 测试 ====================
if __name__ == "__main__":
    print("=" * 50)
    print("requests2 测试")
    print("=" * 50)

    print("\n[1] GET 测试:")
    r = http_request.get("https://www.ipplus360.com/getIP", timeout=10)
    print(f"    {r.text.strip()[:150]}")

    print("\n[2] POST 测试:")
    r = http_request.post("https://httpbin.org/post", json={"hello": "world"}, timeout=10)
    print(f"    origin: {r.json().get('origin', 'N/A')}")
