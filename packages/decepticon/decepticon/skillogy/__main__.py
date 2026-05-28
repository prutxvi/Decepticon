"""``python -m decepticon.skillogy`` - run the Skillogy server.

Boots the FastAPI REST app + optional grpcio service, ingests the
in-container skills directory, and serves traffic until SIGTERM.

Environment variables:
- ``SKILLOGY_REST_PORT``     (default 9100)
- ``SKILLOGY_GRPC_PORT``     (default 50051; gRPC disabled when grpcio absent)
- ``SKILLOGY_SKILLS_ROOT``   (default ``/app/skills``)
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from decepticon.skillogy.server import SkillRegistry, build_app, build_grpc_server, ingest_directory

log = logging.getLogger("skillogy")


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _start_grpc(registry: SkillRegistry, port: int) -> threading.Thread | None:
    try:
        server, _servicer = build_grpc_server(registry, port=port)
    except RuntimeError as exc:
        log.warning("gRPC disabled: %s", exc)
        return None
    server.start()
    log.info("Skillogy gRPC listening on :%d", port)

    def _serve_forever() -> None:
        try:
            server.wait_for_termination()
        finally:
            log.info("Skillogy gRPC shutting down")

    t = threading.Thread(target=_serve_forever, daemon=True)
    t.start()
    return t


def _start_rest(registry: SkillRegistry, port: int, started_at: float) -> None:
    try:
        import uvicorn  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Skillogy REST requires uvicorn. Install with: pip install uvicorn"
        ) from exc
    app = build_app(registry, started_at=started_at)
    config = uvicorn.Config(app=app, host="0.0.0.0", port=port, log_level="info")
    uvicorn.Server(config).run()


def main() -> int:
    _setup_logging()
    rest_port = int(os.environ.get("SKILLOGY_REST_PORT", "9100"))
    grpc_port = int(os.environ.get("SKILLOGY_GRPC_PORT", "50051"))
    skills_root = Path(os.environ.get("SKILLOGY_SKILLS_ROOT", "/app/skills"))

    registry = SkillRegistry()
    started_at = time.time()

    count = ingest_directory(registry, skills_root)
    log.info("Skillogy registry seeded with %d skills from %s", count, skills_root)

    _start_grpc(registry, grpc_port)

    def _handle_term(_signum, _frame):
        log.info("SIGTERM received; exiting")
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_term)

    _start_rest(registry, rest_port, started_at)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
