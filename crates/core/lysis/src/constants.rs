use alloy_primitives::U256;

pub const FLOOR_RATE_PERCENT: u64 = 8;

pub fn calc_floor_price(price: U256) -> U256 {
    price * U256::from(100 + FLOOR_RATE_PERCENT) / U256::from(100u64)
}
