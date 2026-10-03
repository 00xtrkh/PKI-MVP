"""Allow ``python -m pki.web`` to start the HTTP server."""

from __future__ import annotations

import os

from pki.web import create_app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("MINIPKI_HOST", "127.0.0.1")
    port = int(os.getenv("MINIPKI_PORT", "5000"))
    if "MINIPKI_DEBUG" in os.environ:
        debug = os.getenv("MINIPKI_DEBUG", "").strip() in {"1", "true", "True", "yes"}
    else:
        # Local default: debug on loopback; Docker sets MINIPKI_DEBUG=0.
        debug = host in {"127.0.0.1", "localhost"}
    app.run(debug=debug, host=host, port=port)
