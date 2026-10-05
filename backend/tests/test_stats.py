import statistics

import pytest

from app.detection.stats import (
    MAX_SCORE,
    choose_baseline,
    is_anomalous,
    robust_baseline,
    robust_z,
    score_from_z,
)

PER_MINUTE = [20, 22, 19, 25, 21, 600]  # one user's requests per minute; 600 is a burst


def test_mean_and_std_let_the_outlier_hide_itself():
    mean, std = statistics.mean(PER_MINUTE), statistics.pstdev(PER_MINUTE)

    assert round((600 - mean) / std, 2) == 2.24  # would look almost normal


def test_median_and_mad_expose_the_outlier():
    baseline = robust_baseline(PER_MINUTE, floor=1)

    assert (baseline.median, baseline.mad) == (21.5, 2.0)
    assert round(baseline.scale, 2) == 2.97  # 1.4826 * 2.0
    assert round(robust_z(600, baseline)) == 195


def test_mad_of_zero_uses_the_floor_instead_of_dividing_by_zero():
    baseline = robust_baseline([1, 1, 1, 1, 1, 1, 2], floor=1)

    assert baseline.mad == 0
    assert baseline.scale == 1  # absolute floor (10% of median 1 = 0.1 is smaller)
    assert robust_z(2, baseline) == 1.0


def test_relative_floor_applies_for_large_values():
    baseline = robust_baseline([1000, 1000, 1000], floor=1)

    assert baseline.scale == 100  # 10% of the median


def test_empty_values_are_an_error():
    with pytest.raises(ValueError):
        robust_baseline([], floor=1)


@pytest.mark.parametrize(("z", "score"), [(0, 0.0), (-3, 0.0), (6, 0.45), (10, 0.63), (20, 0.86)])
def test_score_table(z, score):
    assert round(score_from_z(z), 2) == score


def test_score_is_monotonic_and_capped():
    scores = [score_from_z(z) for z in range(0, 200)]

    assert scores == sorted(scores)
    assert max(scores) == MAX_SCORE


def test_user_baseline_when_enough_history_else_population():
    population = list(range(1, 101))

    _, kind = choose_baseline([5] * 20, population, min_points=20, floor=1)
    assert kind == "user"
    baseline, kind = choose_baseline([5, 6, 7], population, min_points=20, floor=1)
    assert kind == "population" and baseline.n == 100


def test_flag_needs_both_statistical_and_practical_significance():
    baseline = robust_baseline([10_000] * 50, floor=1_000)  # a user who sends ~10 KB per hour

    assert not is_anomalous(300_000, baseline, min_effect=50_000_000)  # unusual but tiny: no
    assert is_anomalous(400_000_000, baseline, min_effect=50_000_000)  # unusual and big: yes
    assert not is_anomalous(10_500, baseline, min_effect=0)  # big enough but not unusual: no
