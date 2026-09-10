use crate::schema::PromisLimitContract;
use alloy_primitives::U256;
use outbe_primitives::error::Result;

impl PromisLimitContract<'_> {
    pub fn get_total_unallocated(&self) -> Result<U256> {
        self.total_unallocated.read()
    }

    pub fn set_total_unallocated(&mut self, total: U256) -> Result<()> {
        self.total_unallocated.write(total)
    }

    pub fn add_to_total_unallocated(&mut self, amount: U256) -> Result<()> {
        self.checked_add_carry_over(amount).map(|_| ())
    }
}
