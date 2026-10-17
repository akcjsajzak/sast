"""Optional web interface for the scanner (`sast server`)."""
from .server import DEFAULT_DATA_DIR, make_server, serve
from .store import ScanStore

__all__ = ["serve", "make_server", "ScanStore", "DEFAULT_DATA_DIR"]
