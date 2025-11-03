"""CMMC/NIST control definitions and mappings."""
from .control_families import CONTROL_FAMILIES, get_family_description
from .cmmc_l2 import CMMC_L2_PRACTICES

__all__ = [
    "CONTROL_FAMILIES",
    "get_family_description",
    "CMMC_L2_PRACTICES",
]
