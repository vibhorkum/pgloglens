"""Pure-Python utility functions — no compiled dependencies."""
from __future__ import annotations

from typing import List, Optional


def percentile(sorted_data: List[float], p: float) -> float:
    """Compute the p-th percentile of a pre-sorted list (0 <= p <= 100).

    Uses linear interpolation (same method as numpy.percentile with default settings).
    """
    if not sorted_data:
        return 0.0
    n = len(sorted_data)
    if n == 1:
        return sorted_data[0]
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = lo + 1
    frac = idx - lo
    if hi >= n:
        return sorted_data[-1]
    return sorted_data[lo] + frac * (sorted_data[hi] - sorted_data[lo])


def linear_regression_slope(values: List[float]) -> float:
    """Return the slope of a simple OLS linear regression y ~ x.

    x is the index sequence 0, 1, ..., n-1.
    This is a pure-Python replacement for numpy.polyfit(x, y, 1)[0].
    """
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2.0
    y_mean = sum(values) / n
    numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
    denominator = sum((i - x_mean) ** 2 for i in range(n))
    if denominator == 0:
        return 0.0
    return numerator / denominator
