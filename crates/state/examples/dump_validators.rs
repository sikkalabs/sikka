use sikka_common::amount::format_sikka;
use sikka_state::StateStore;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: dump_validators <state.redb>");
    let store = StateStore::open(&path).expect("open");
    let vals = store.all_validators().expect("validators");
    println!("address,bond_chillar,bond_sikka,active_from,unbonding_since");
    for v in &vals {
        println!(
            "{},{},{},{},{:?}",
            v.address,
            v.bond,
            format_sikka(v.bond),
            v.active_from,
            v.unbonding_since
        );
    }
    eprintln!("validators={}", vals.len());
}
