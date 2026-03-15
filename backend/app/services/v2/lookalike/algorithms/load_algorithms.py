"""
Lookalike algorithm loader.

Importing this module triggers registration of all lookalike detection
algorithms via registry.register().

Usage (in the lookalike scan runner):
    from app.services.v2.lookalike.algorithms import load_algorithms
"""

from . import levenshtein
from . import homoglyph
from . import keyboard_swap
from . import tld_swap