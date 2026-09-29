# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Environment bootstrap for Cloudtop development.

Automatically ensures that local virtualenv dependencies (such as google-genai,
mcp, starlette, etc.) are available on sys.path and within namespace packages
when launched via global or system python runners (e.g. ~/.local/bin/uvicorn).
"""

from pathlib import Path
import sys


def bootstrap_environment():
  """Inject project virtualenv site-packages into sys.path."""
  py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
  home = Path.home()
  repo_root = Path(__file__).resolve().parent.parent

  candidates = [
      repo_root / ".venv" / "lib" / py_ver / "site-packages",
      home / "projects" / "secops-regress" / ".venv" / "lib" / py_ver / "site-packages",
      home / "projects" / "agentic_ueba" / ".venv" / "lib" / py_ver / "site-packages",
  ]

  for p in candidates:
    if p.is_dir() and str(p) not in sys.path:
      sys.path.insert(0, str(p))
      if "google" in sys.modules:
        google_mod = sys.modules["google"]
        google_dir = p / "google"
        if google_dir.is_dir() and hasattr(google_mod, "__path__"):
          if str(google_dir) not in google_mod.__path__:
            google_mod.__path__.append(str(google_dir))


bootstrap_environment()
