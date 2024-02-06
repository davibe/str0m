// Add the necessary dependencies in your Cargo.toml file:

mod common;
use common::pair::LtoR;

use divan::{black_box, Bencher};

#[divan::bench]
pub fn vp8_unidirectional(bencher: Bencher) {
    bencher
        .with_inputs(|| LtoR::with_vp8_input())
        .bench_local_refs(|server_ref| {
            let _ = black_box(black_box(server_ref).run().expect("error"));
        });
}

#[divan::bench]
pub fn vp9_unidirectional(bencher: Bencher) {
    bencher
        .with_inputs(|| LtoR::with_vp8_input())
        .bench_local_refs(|server_ref| {
            let _ = black_box(black_box(server_ref).run().expect("error"));
        });
}

fn main() {
    divan::main();
}


