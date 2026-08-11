use sikka_common::amount::format_sikka;
use sikka_common::constants::CHILLAR_PER_SIKKA;
use sikka_state::StateStore;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_balances <state.redb>");
    let store = StateStore::open(&path).expect("open state.redb");
    let accounts = store.all_accounts().expect("read accounts");
    println!("address,balance_chillar,balance_sikka,nonce,battery,last_regen_time");
    let mut total = 0u64;
    for (addr, acc) in &accounts {
        total = total.saturating_add(acc.balance);
        println!(
            "{},{},{},{},{},{}",
            addr,
            acc.balance,
            format_sikka(acc.balance),
            acc.nonce,
            acc.battery,
            acc.last_regen_time
        );
    }
    eprintln!(
        "accounts={} total_sikka={} ({} chillar)",
        accounts.len(),
        format_sikka(total),
        total
    );
    let _ = CHILLAR_PER_SIKKA;
}
