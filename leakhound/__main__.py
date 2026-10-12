"""Allow ``python -m leakhound``."""

import sys

from .cli import main

sys.exit(main())
