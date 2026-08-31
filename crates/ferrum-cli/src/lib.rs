//! Library half of `ferrumctl`. The binary is a thin argument parser over
//! these modules; the testkit gates the deploy tree through the same code the
//! CLI runs, not a copy of it.

pub mod break_glass;
pub mod compile;
pub mod fsig;
pub mod gen_pki;
pub mod lint_deploy;
pub mod sign;
pub mod validate;
pub mod verify;
