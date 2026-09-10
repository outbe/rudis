"""Independent Decimal reference for the two-phase emission curve.

Run this script to regenerate vectors.json. No Rust output is used as input.
"""
from decimal import Decimal, localcontext
import json
from pathlib import Path


def generate():
    with localcontext() as context:
        context.prec = 80
        floor = Decimal(2) ** 26
        initial = Decimal(2) ** 28
        peak = 26 * floor / 3
        k1, k2 = Decimal(128), Decimal(384)

        def tanh(x):
            exponential = (2 * x).exp()
            return (exponential - 1) / (exponential + 1)

        amplitude = (peak - initial) / tanh(Decimal(512) / (2 * k1))
        offset1 = (initial + peak - amplitude) / 2
        decline = (peak - floor) / tanh(Decimal(1024) / (2 * k2))
        offset2 = (peak + floor + decline) / 2
        days = []
        for day in range(3073):
            if day == 0:
                value = initial
            elif day == 3072:
                value = floor
            elif day <= 1024:
                value = offset1 + amplitude / (1 + ((512 - day) / k1).exp())
            else:
                value = offset2 - decline / (1 + ((2048 - day) / k2).exp())
            days.append({"day": day, "emission_units": str(int(max(floor, value) * 1_000_000))})
        return {"days": days}


if __name__ == "__main__":
    Path(__file__).with_name("vectors.json").write_text(json.dumps(generate(), indent=2) + "\n")
