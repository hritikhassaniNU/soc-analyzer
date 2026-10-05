"""Statistics core shared by the behavioral detectors (pure functions, no database).

The question every detector asks: "is this value unusually HIGH for this user?"

- Robust baseline: median and MAD (median absolute deviation) instead of mean and standard
  deviation. The attack is part of the data the baseline is computed from; a mean/std gets dragged
  toward the outlier so the outlier hides itself, while median/MAD barely move.
  Example (requests per minute 20, 22, 19, 25, 21, 600): mean/std gives z = 2.2 (looks normal),
  median/MAD gives robust z = 195.
- Spread floor: if most values are identical, MAD is 0 and any deviation would look infinitely
  unusual; the scale is never below a floor.
- Minimum history: users with too few data points are compared to the population instead.
- Score: 1 - e^(-z/10), capped at 0.99. A ranking signal, not a probability.
"""

import math
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

MAD_TO_STD = 1.4826  # makes MAD comparable to a standard deviation for normally distributed data
RELATIVE_FLOOR = 0.10  # the scale is at least 10% of the median
Z_THRESHOLD = 6.0  # conservative: we test thousands of user-minutes, so chance outliers are common
SCORE_K = 10.0
MAX_SCORE = 0.99


@dataclass(frozen=True)
class Baseline:
    median: float
    mad: float
    scale: float  # max(1.4826 * MAD, 10% of median, absolute floor): never zero
    n: int  # how many data points the baseline was built from


def robust_baseline(values: Sequence[float], floor: float) -> Baseline:
    """Median + robust scale of `values`. `floor` is the smallest meaningful spread for this metric
    (e.g. 1 request per minute, 1 MB per hour)."""
    if not values:
        raise ValueError("A baseline needs at least one value")
    median = statistics.median(values)
    mad = statistics.median(abs(v - median) for v in values)
    scale = max(MAD_TO_STD * mad, RELATIVE_FLOOR * median, floor)
    return Baseline(median=median, mad=mad, scale=scale, n=len(values))


def robust_z(value: float, baseline: Baseline) -> float:
    """How many robust 'standard deviations' above the median `value` is (negative if below)."""
    return (value - baseline.median) / baseline.scale


def score_from_z(z: float) -> float:
    """Monotonic 0..0.99 ranking signal: z=6 -> 0.45, z=10 -> 0.63, z=20 -> 0.86, z>=50 -> 0.99."""
    if z <= 0:
        return 0.0
    return min(MAX_SCORE, 1 - math.exp(-z / SCORE_K))


def choose_baseline(
    user_values: Sequence[float],
    population_values: Sequence[float],
    min_points: int,
    floor: float,
) -> tuple[Baseline, Literal["user", "population"]]:
    """The user's own baseline when they have enough history, otherwise everyone's."""
    if len(user_values) >= min_points:
        return robust_baseline(user_values, floor), "user"
    return robust_baseline(population_values, floor), "population"


def is_anomalous(value: float, baseline: Baseline, min_effect: float) -> bool:
    """Statistically unusual (z >= 6) AND practically meaningful (at least `min_effect`)."""
    return robust_z(value, baseline) >= Z_THRESHOLD and value >= min_effect
