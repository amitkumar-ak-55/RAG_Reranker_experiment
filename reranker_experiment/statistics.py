from __future__ import annotations

import math
import random
from collections.abc import Sequence


def paired_bootstrap(
    left: Sequence[float],
    right: Sequence[float],
    *,
    seed: int = 17,
    iterations: int = 10_000,
) -> tuple[float, float]:
    if len(left) != len(right):
        raise ValueError("paired bootstrap inputs must have equal lengths")
    if not left:
        return 0.0, 0.0
    differences = [a - b for a, b in zip(left, right)]
    rng = random.Random(seed)
    means = [sum(rng.choices(differences, k=len(differences))) / len(differences) for _ in range(iterations)]
    means.sort()
    return means[int(iterations * 0.025)], means[int(iterations * 0.975) - 1]


def holm_adjust(p_values: Sequence[float]) -> list[float]:
    ordered = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [1.0] * len(p_values)
    running = 0.0
    for rank, (index, value) in enumerate(ordered):
        running = max(running, min(1.0, (len(p_values) - rank) * value))
        adjusted[index] = running
    return adjusted


def rank_biserial(left: Sequence[float], right: Sequence[float]) -> float:
    differences = [a - b for a, b in zip(left, right) if a != b]
    positive = sum(value > 0 for value in differences)
    negative = sum(value < 0 for value in differences)
    return (positive - negative) / len(differences) if differences else 0.0


def wilcoxon_signed_rank(left: Sequence[float], right: Sequence[float]) -> tuple[float, float]:
    """Return the signed-rank statistic and a normal-approximation p-value.

    The implementation is dependency-free; ties and zero differences are
    omitted, and the p-value is explicitly labelled an approximation.
    """
    differences = [a - b for a, b in zip(left, right) if a != b]
    if not differences:
        return 0.0, 1.0
    ranked = sorted((abs(value), index, value) for index, value in enumerate(differences))
    ranks: list[float] = [0.0] * len(ranked)
    position = 0
    while position < len(ranked):
        end = position + 1
        while end < len(ranked) and ranked[end][0] == ranked[position][0]:
            end += 1
        average = (position + 1 + end) / 2
        for index in range(position, end):
            ranks[index] = average
        position = end
    positive = sum(rank for rank, (_, _, value) in zip(ranks, ranked) if value > 0)
    negative = sum(rank for rank, (_, _, value) in zip(ranks, ranked) if value < 0)
    statistic = min(positive, negative)
    count = len(differences)
    mean = count * (count + 1) / 4
    variance = count * (count + 1) * (2 * count + 1) / 24
    z = (statistic - mean) / math.sqrt(variance)
    p_value = math.erfc(abs(z) / math.sqrt(2))
    return statistic, p_value

