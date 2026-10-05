from __future__ import annotations

import uvicorn

from .api import create_app
from .config import load as load_config


def run() -> None:
    """Start the uvicorn server with TLS if configured."""
    cfg = load_config()
    host, _, port = cfg.listen.partition(":")
    port_i = int(port or "8443")
    app = create_app(cfg)
    uvicorn.run(
        app,
        host=host or "0.0.0.0",
        port=port_i,
        ssl_certfile=cfg.tls_cert,
        ssl_keyfile=cfg.tls_key,
    )
