# protocols/__init__.py
import importlib
from pathlib import Path

PROTOCOL_DIR = Path(__file__).parent

def get_parser(protocol_name):
    try:
        mod = importlib.import_module(f"protocols.{protocol_name}")
        return getattr(mod, "parse", None)
    except Exception:
        return None
