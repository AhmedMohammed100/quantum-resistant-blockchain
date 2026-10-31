from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import ssl
import threading
import time
from urllib.parse import parse_qs, urlparse

from .api_common import RequestBodyTooLarge
from .api_get_routes import GetRoutesMixin
from .api_post_routes import PostRoutesMixin
from .config import NodeConfig
from .rate_limit import enforce_redis_rate_limit
from .service import NodeService


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with a hard cap on concurrent request handlers."""

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        *,
        max_concurrent_requests: int = 64,
        **kwargs,
    ) -> None:
        if max_concurrent_requests <= 0:
            raise ValueError("Maximum concurrent HTTP requests must be positive.")
        self._request_slots = threading.BoundedSemaphore(max_concurrent_requests)
        super().__init__(server_address, RequestHandlerClass, **kwargs)

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            # Refuse excess work promptly instead of creating more handler
            # threads while existing requests occupy the configured limit.
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class NodeRequestHandler(GetRoutesMixin, PostRoutesMixin, BaseHTTPRequestHandler):
    service: NodeService
    _transaction_rate_lock = threading.Lock()
    _transaction_rate_windows: dict[str, tuple[float, int]] = {}

    def setup(self) -> None:
        super().setup()
        timeout = float(getattr(self.service.config, "http_client_timeout_seconds", 10.0))
        if timeout <= 0:
            timeout = 10.0
        # Bound idle header/body reads so slow clients cannot hold worker threads
        # indefinitely. Reverse proxies should enforce their own header limits too.
        self.connection.settimeout(timeout)

    def _operator_auth_required(self) -> bool:
        """Require a bearer token for privileged HTTP operations.

        Loopback development nodes remain convenient without a token. Any
        non-loopback bind is denied for privileged operations unless an
        explicit API token is configured.
        """
        token = str(self.service.config.api_auth_token or "")
        bind_host = str(self.server.server_address[0])
        loopback = bind_host in {"127.0.0.1", "::1", "localhost"}
        secure_deployment = str(self.service.config.deployment_mode).lower() not in {"development", "test"}
        return bool(token) or not loopback or secure_deployment

    def _authorize_operator(self) -> bool:
        if not self._operator_auth_required():
            return True
        expected = str(self.service.config.api_auth_token or "")
        if not expected:
            self._respond(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Privileged API operations require QR_CHAIN_API_AUTH_TOKEN on non-loopback binds."},
                headers={"Retry-After": "0"},
            )
            return False
        authorization = self.headers.get("Authorization", "")
        prefix = "Bearer "
        provided = authorization[len(prefix):].strip() if authorization.startswith(prefix) else ""
        if not provided or not hmac.compare_digest(provided, expected):
            self._respond(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Operator authentication required."},
                headers={"WWW-Authenticate": "Bearer"},
            )
            return False
        return True

    def log_message(self, format: str, *args: object) -> None:
        return

    def _allow_public_transaction(self) -> bool:
        limit = int(getattr(self.service.config, "max_public_transaction_requests_per_minute", 60))
        if limit <= 0:
            self._respond(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Public transaction rate limit is disabled by invalid configuration."},
                headers={"Retry-After": "60"},
            )
            return False
        client = str(getattr(self, "client_address", ("unknown",))[0])
        redis_url = str(getattr(self.service.config, "transaction_rate_limit_redis_url", "") or "").strip()
        if redis_url:
            # A configured shared backend is fail-closed. Do not silently fall
            # back to per-process limits if Redis is unavailable.
            client_key = hashlib.sha256(client.encode("utf-8")).hexdigest()
            try:
                retry_after = enforce_redis_rate_limit(
                    redis_url,
                    f"qbc:public-tx:{client_key}",
                    limit,
                    window_seconds=60,
                )
            except (OSError, ValueError, ConnectionError, TimeoutError):
                self._respond(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": "Shared transaction rate limiter is unavailable."},
                    headers={"Retry-After": "5"},
                )
                return False
            if retry_after is not None:
                self._respond(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "Public transaction request rate exceeded."},
                    headers={"Retry-After": str(retry_after)},
                )
                return False
            return True
        deployment_mode = str(getattr(self.service.config, "deployment_mode", "development")).strip().lower()
        if deployment_mode not in {"development", "test"}:
            self._respond(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "A shared Redis transaction rate limiter is required outside development/test mode."},
                headers={"Retry-After": "5"},
            )
            return False
        now = time.monotonic()
        retry_after = 0
        handler_type = type(self)
        with handler_type._transaction_rate_lock:
            # Bound bookkeeping if clients churn through many source addresses.
            expired_before = now - 60.0
            if len(handler_type._transaction_rate_windows) > 4096:
                active_windows = {
                    key: value for key, value in handler_type._transaction_rate_windows.items()
                    if value[0] > expired_before
                }
                if len(active_windows) > 4096:
                    # Keep the newest windows if source-address churn exceeds
                    # the hard bookkeeping cap.
                    active_windows = dict(
                        sorted(active_windows.items(), key=lambda item: item[1][0])[-2048:]
                    )
                handler_type._transaction_rate_windows = active_windows
            started, count = handler_type._transaction_rate_windows.get(client, (now, 0))
            if now - started >= 60.0:
                started, count = now, 0
            if count >= limit:
                retry_after = max(1, int(60.0 - (now - started)))
            else:
                handler_type._transaction_rate_windows[client] = (started, count + 1)
        if retry_after:
            self._respond(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Public transaction request rate exceeded."},
                headers={"Retry-After": str(retry_after)},
            )
            return False
        return True

    def _read_json(self) -> dict[str, object]:
        limit = int(getattr(self.service.config, "max_api_request_bytes", 20971520))
        if limit <= 0:
            raise ValueError("Configured maximum API request size must be positive.")
        lengths = self.headers.get_all("Content-Length", []) if hasattr(self.headers, "get_all") else []
        if len(lengths) > 1 and len({item.strip() for item in lengths}) != 1:
            raise ValueError("Conflicting Content-Length headers are not allowed.")
        if self.headers.get("Transfer-Encoding") is not None:
            raise ValueError("Transfer-Encoding is not supported by this JSON API.")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type and content_type != "application/json":
            raise ValueError("Content-Type must be application/json.")
        raw_length = self.headers.get("Content-Length", "0")
        try:
            content_length = int(raw_length)
        except (TypeError, ValueError) as error:
            raise ValueError("Content-Length must be a valid non-negative integer.") from error
        if content_length < 0:
            raise ValueError("Content-Length must be a valid non-negative integer.")
        if content_length > limit:
            raise RequestBodyTooLarge("Request body exceeds the configured size limit.")
        # Respect HTTP Content-Length exactly; reading one extra byte can block
        # waiting for the next request or consume its first byte on keep-alive.
        raw = self.rfile.read(content_length) if content_length else b"{}"
        if len(raw) > limit:
            raise RequestBodyTooLarge("Request body exceeds the configured size limit.")
        if not raw:
            return {}
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Body must contain valid UTF-8 JSON.") from error
        if not isinstance(decoded, dict):
            raise ValueError("JSON request body must be an object.")
        return decoded

    def _respond(
        self,
        status: HTTPStatus,
        payload: dict[str, object],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)


def serve(config: NodeConfig) -> None:
    tls_enabled = config.validate_inbound_tls()
    service = NodeService(config)
    service.enforce_security_policy_profile()

    class Handler(NodeRequestHandler):
        pass

    Handler.service = service
    server = BoundedThreadingHTTPServer(
        (config.host, config.port),
        Handler,
        max_concurrent_requests=config.max_http_concurrent_requests,
    )
    if tls_enabled:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(config.tls_cert_file, config.tls_key_file)
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if tls_enabled else "http"
    print(f"Quantum-resistant node listening on {scheme}://{config.host}:{config.port}")
    server.serve_forever()
