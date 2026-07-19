# Make dns_module importable as a package
# Re-export commonly used submodules for convenience
from . import dns_lookup

# Single source of truth for the deployed version (also in pyproject.toml).
# Consumers and the observatory fingerprint guard read this to detect drift.
__version__ = "1.2.0"
