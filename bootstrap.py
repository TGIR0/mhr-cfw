"""
Project import-path bootstrap.

Keeps the historical flat imports working when the repo is run directly from
Windows or POSIX without requiring installation as a package.
"""

from __future__ import annotations

import os
import sys

_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)
