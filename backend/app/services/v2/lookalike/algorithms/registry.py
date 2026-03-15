# registry.py
#
# Registry for lookalike detection algorithms.
# Algorithms register themselves here rather than being hardcoded
# into the lookalike scan family runner.

ALGORITHMS = []

def register(algorithm):
    """
    Register a lookalike detection algorithm.
    Call this at module load time in each algorithm file.
    """
    ALGORITHMS.append(algorithm)
