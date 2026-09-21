import os
import sys

# Make the reconx package modules (reconx.py, reconx_notes.py) importable when
# pytest is run from anywhere - they live one level up from this tests/ dir and
# are single files, not an installed package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
