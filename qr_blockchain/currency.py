from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CurrencyPolicy:
    name: str
    symbol: str
    decimals: int
    base_unit: str
    initial_subsidy: int
    subsidy_halving_interval: int
    max_money: int
    genesis_supply_cap: int = 0

    def subsidy_at_height(self, height: int) -> int:
        if height <= 0:
            return 0
        if self.subsidy_halving_interval <= 0:
            return self.initial_subsidy
        halvings = height // self.subsidy_halving_interval
        if halvings >= 63:
            return 0
        return self.initial_subsidy >> halvings

    def cumulative_subsidy_through_height(self, height: int) -> int:
        if height <= 0:
            return 0
        total = 0
        current_height = 1
        while current_height <= height:
            subsidy = self.subsidy_at_height(current_height)
            if subsidy == 0:
                break
            if self.subsidy_halving_interval <= 0:
                total += subsidy * (height - current_height + 1)
                break
            next_halving = ((current_height // self.subsidy_halving_interval) + 1) * self.subsidy_halving_interval
            segment_end = min(height, max(current_height, next_halving - 1))
            total += subsidy * (segment_end - current_height + 1)
            current_height = segment_end + 1
        return total

    def units_per_coin(self) -> int:
        return 10 ** self.decimals

    def describe(self, *, height: int = 0) -> dict[str, object]:
        return {
            "name": self.name,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "base_unit": self.base_unit,
            "units_per_coin": self.units_per_coin(),
            "initial_subsidy": self.initial_subsidy,
            "subsidy_halving_interval": self.subsidy_halving_interval,
            "subsidy_at_next_height": self.subsidy_at_height(height + 1),
            "issued_subsidy_through_height": self.cumulative_subsidy_through_height(height),
            "genesis_supply_cap": self.genesis_supply_cap,
            "max_money": self.max_money,
        }


def format_units(amount: int, *, decimals: int, symbol: str) -> str:
    sign = "-" if amount < 0 else ""
    value = abs(amount)
    scale = 10 ** decimals
    whole = value // scale
    fraction = value % scale
    if decimals == 0:
        return f"{sign}{whole} {symbol}"
    return f"{sign}{whole}.{fraction:0{decimals}d} {symbol}"
