#!/usr/bin/env python3
"""RCFI reference implementation - golden oracle for the Rust `outbe-fidelity` crate.

This is the PDF "Retention component - time decay" reference (`decay.py`), trimmed
to the pure model (no matplotlib/pandas/numpy) plus a stdlib-only golden-vector
emitter. The Rust crate's cohort engine must reproduce these vectors.

Regenerate the committed fixture with:

    python3 reference/decay.py --emit-golden > tests/fixtures/rcfi_golden.json

Amounts are emitted in six-decimal GRATIS units;
timestamps are UTC unix seconds. RCFI / efficiency / d_age are the float-model
reference values the Rust integer model is checked against (+/-1 day / +/-1e-3).
"""

import json
import math
import sys
from datetime import datetime, timedelta, timezone

H_DAYS = 365.0                       # Half-Life
L_CONST = H_DAYS / math.log(2)       # Limit constant L = H/ln2
AMOUNT_SCALE = 10 ** 6               # GRATIS-unit per whole GRATIS


def get_decayed_time(days_passed):
    """Tdec = L * (1 - (1/2)^(T/H)); negative ages clamp to 0."""
    if days_passed < 0:
        return 0.0
    return L_CONST * (1 - math.pow(0.5, days_passed / H_DAYS))


class Cohort:
    def __init__(self, date, amount):
        self.date = date
        self.current_amount = amount
        self.sales = []


class Wallet:
    def __init__(self):
        self.cohorts = []
        self.balance = 0.0
        self.first_qualified_date = None

    def deposit(self, date, amount):
        self.cohorts.append(Cohort(date, amount))
        self.balance += amount
        if self.first_qualified_date is None:
            self.first_qualified_date = date

    def withdraw(self, date, amount):
        # LIFO: youngest cohorts sold first.
        amount_left_to_sell = abs(amount)
        self.balance -= amount_left_to_sell
        for cohort in reversed(self.cohorts):
            if amount_left_to_sell <= 1e-9:
                break
            if cohort.current_amount > 0:
                sell_from_cohort = min(cohort.current_amount, amount_left_to_sell)
                cohort.sales.append({'date': date, 'amount': sell_from_cohort})
                cohort.current_amount -= sell_from_cohort
                amount_left_to_sell -= sell_from_cohort

    def calculate_metrics(self, current_date):
        if self.first_qualified_date is None or current_date < self.first_qualified_date:
            return 0.0, 0.0, 0.0, self.balance
        numerator = 0.0
        denominator = 0.0
        for cohort in self.cohorts:
            age_days = (current_date - cohort.date).total_seconds() / 86400.0
            t_dec_buy = get_decayed_time(age_days)
            if cohort.current_amount > 0:
                contribution = cohort.current_amount * t_dec_buy
                numerator += contribution
                denominator += contribution
            for sale in cohort.sales:
                sale_age_days = (current_date - sale['date']).total_seconds() / 86400.0
                if sale_age_days < 0:
                    continue
                t_dec_sell = get_decayed_time(sale_age_days)
                denominator += sale['amount'] * (t_dec_buy - t_dec_sell)
        efficiency = numerator / denominator if denominator > 1e-9 else 0.0
        wallet_age_days = (current_date - self.first_qualified_date).total_seconds() / 86400.0
        d_age = get_decayed_time(wallet_age_days)
        return d_age * efficiency, efficiency, d_age, self.balance


# The bundled scenario from the PDF reference. Positive = deposit (mine Gratis
# from nod), negative = withdraw (mine COEN from Gratis).
SCENARIO = [
    {"date": "2024-09-01T10:00:00", "amount": 0.2},
    {"date": "2024-12-01T12:00:00", "amount": 3},
    {"date": "2025-03-01T10:00:00", "amount": 10},
    {"date": "2025-04-10T10:00:00", "amount": 2},
    {"date": "2025-04-20T10:00:00", "amount": -1},
    {"date": "2025-05-10T10:00:00", "amount": 2.2},
    {"date": "2025-05-20T10:00:00", "amount": -1.4},
    {"date": "2025-06-10T10:00:00", "amount": 2},
    {"date": "2025-06-20T10:00:00", "amount": -1.3},
    {"date": "2025-07-15T11:00:00", "amount": -10},
    {"date": "2025-07-30T18:00:00", "amount": 8},
    {"date": "2025-09-20T18:00:00", "amount": 15},
    {"date": "2025-09-22T18:00:00", "amount": -15},
    {"date": "2026-11-01T18:00:00", "amount": 20},
    {"date": "2027-11-01T18:00:00", "amount": 1},
]


def _utc(dt):
    return dt.replace(tzinfo=timezone.utc)


def _secs(dt):
    return int(_utc(dt).timestamp())


def emit_golden():
    txs = []
    for tx in SCENARIO:
        txs.append({"dt": datetime.fromisoformat(tx["date"]), "amount": float(tx["amount"])})
    txs.sort(key=lambda x: x["dt"])

    # Sample at each transaction instant plus two later horizons.
    sample_dts = [t["dt"] for t in txs]
    sample_dts.append(txs[-1]["dt"] + timedelta(days=30))
    sample_dts.append(txs[-1]["dt"] + timedelta(days=400))

    transactions = []
    for t in txs:
        kind = "deposit" if t["amount"] >= 0 else "withdraw"
        amount_units = round(abs(t["amount"]) * AMOUNT_SCALE)
        transactions.append({"ts": _secs(t["dt"]), "kind": kind, "amount_units": str(amount_units)})

    samples = []
    for cur in sample_dts:
        wallet = Wallet()
        for t in txs:
            if t["dt"] <= cur:
                if t["amount"] >= 0:
                    wallet.deposit(t["dt"], t["amount"])
                else:
                    wallet.withdraw(t["dt"], t["amount"])
        rcfi, eff, d_age, bal = wallet.calculate_metrics(cur)
        samples.append({
            "ts": _secs(cur),
            "rcfi": rcfi,
            "efficiency": eff,
            "d_age": d_age,
            "balance": bal,
        })

    print(json.dumps({"transactions": transactions, "samples": samples}, indent=2))


if __name__ == "__main__":
    if "--emit-golden" in sys.argv:
        emit_golden()
    else:
        print("usage: python3 decay.py --emit-golden > tests/fixtures/rcfi_golden.json", file=sys.stderr)
        sys.exit(1)
