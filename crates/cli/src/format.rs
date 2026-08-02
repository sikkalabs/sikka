//! Human-readable output.
//!
//! Amounts are always printed in SIKKA with the CHILLAR value alongside where it
//! matters, because a wallet that shows `1000000000` when you meant one coin is
//! a wallet that loses money.

use sikka_common::amount::format_sikka;
use sikka_common::checkpoint::Checkpoint;
use sikka_common::error::{Error, Result};
use sikka_rpc::types::{AccountInfo, ChainInfo, ValidatorInfo};

pub fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(Error::from)?;
    println!("{json}");
    Ok(())
}

pub fn print_account(info: &AccountInfo) {
    if !info.exists {
        println!("{}", info.address);
        println!("this address has never received coins");
        return;
    }
    println!("{}", info.address);
    println!("balance      {} SIKKA", format_sikka(info.balance));
    println!("nonce        {}", info.nonce);
    println!("next nonce   {}", info.next_nonce);
    println!("battery      {} available now", info.battery_now);
    if let Some(seconds) = info.seconds_until_battery {
        println!("             next charge in {seconds}s");
    }
    if let Some(bond) = info.bond {
        println!("bond         {} SIKKA", format_sikka(bond));
    }
}

pub fn print_chain_info(info: &ChainInfo) {
    println!("chain          {}", info.chain_id);
    println!("height         {}", info.height);
    println!("state root     {}", info.state_root);
    println!(
        "checkpoint     {} at {}",
        info.last_checkpoint_hash, info.last_checkpoint_time
    );
    println!("supply         {} SIKKA", format_sikka(info.total_supply));
    println!(
        "bonded         {} SIKKA ({:.1}%)",
        format_sikka(info.total_bonded),
        percentage(info.total_bonded, info.total_supply)
    );
    println!("accounts       {}", info.accounts);
    println!("validators     {} active", info.active_validators);
    println!(
        "interval       {} transactions per checkpoint",
        info.checkpoint_tx_interval
    );
    println!("mempool        {} pending", info.mempool);
    println!("peers          {}", info.peers);
    println!(
        "node           {}{}",
        info.node_address,
        if info.validator { " (validator)" } else { "" }
    );
}

pub fn print_validators(validators: &[ValidatorInfo]) {
    if validators.is_empty() {
        println!("no validators");
        return;
    }
    for validator in validators {
        let state = if validator.slashed {
            "slashed"
        } else if validator.unbonding_since.is_some() {
            "unbonding"
        } else if validator.active {
            "active"
        } else {
            "pending"
        };
        println!(
            "{}  {:>18} SIKKA  {state}",
            validator.address,
            format_sikka(validator.bond)
        );
    }
}

pub fn print_checkpoint(checkpoint: &Checkpoint) {
    let header = &checkpoint.header;
    println!("height         {}", header.height);
    println!("hash           {}", checkpoint.hash());
    println!("previous       {}", header.prev_hash);
    println!("state root     {}", header.state_root);
    println!("validator root {}", header.validator_root);
    println!("transactions   {}", header.tx_count);
    println!("timestamp      {}", header.timestamp);
    println!("proposer       {}", header.proposer);
    println!("supply         {} SIKKA", format_sikka(header.total_supply));
    println!("bonded         {} SIKKA", format_sikka(header.total_bonded));
    println!("signatures     {}", checkpoint.validator_signatures.len());
}

fn percentage(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 / whole as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentages_do_not_divide_by_zero() {
        assert_eq!(percentage(0, 0), 0.0);
        assert_eq!(percentage(1, 4), 25.0);
    }
}
