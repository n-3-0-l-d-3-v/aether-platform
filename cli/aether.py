#!/usr/bin/env python3
"""Run the Aether CLI without installing the package.

    python cli/aether analyze examples/firmware_agent.elf

Installing with 'pip install -e .' provides the same thing as an 'aether'
command on PATH; this script exists so the repository is usable immediately.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aether.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
