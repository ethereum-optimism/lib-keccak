use std::fmt::Write;

use anyhow::{bail, Result};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressState, ProgressStyle};
use rand::Rng;
use revm::{
    db::{CacheDB, DatabaseRef, EmptyDB},
    primitives::{hex, AccountInfo, Bytecode, TransactTo, U256},
    EVM,
};
use tokio::task::JoinSet;

mod constants;
use constants::{STATEFUL_SPONGE_ADDR, STATEFUL_SPONGE_BYTECODE};

mod hashing;
use hashing::{hash_input_evm, hash_input_tiny};

/// CLI args for the fuzzing tool.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, default_value = "4")]
    thread_count: u64,

    #[arg(short, long, default_value = "100000")]
    diff_count: u64,

    #[arg(short, long, default_value = "100")]
    max_input_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        thread_count,
        diff_count,
        max_input_bytes,
    } = Args::parse();

    let progress_group = MultiProgress::new();
    let progress_style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:60.cyan/blue}] ({msg} | eta: {eta})",
    )?
    .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
        write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
    })
    .progress_chars("#>-");

    let num_hashes = diff_count / thread_count;

    let mut join_set = JoinSet::new();
    for i in 0..thread_count {
        let pb = progress_group.add(ProgressBar::new(num_hashes));
        pb.set_style(progress_style.clone());
        pb.set_message(format!("Thread {}", i + 1));

        join_set.spawn(fuzz_task(pb, num_hashes, max_input_bytes));
    }

    while let Some(res) = join_set.join_next().await {
        res??;
    }

    Ok(())
}

/// Spawns a task that runs through `num_hashes` iterations of differential testing `tiny-keccak` vs.
/// the `StatefulSponge` contract.
#[allow(unused)]
async fn fuzz_task(pb: ProgressBar, num_hashes: u64, max_input_bytes: usize) -> Result<()> {
    // Init EVM
    let mut cache_db = CacheDB::new(EmptyDB::default());
    deploy_contract(&mut cache_db);
    let mut evm = EVM::new();
    evm.database(cache_db);

    // Init EVM
    evm.env.cfg.disable_base_fee = true;
    evm.env.cfg.disable_gas_refund = true;
    evm.env.cfg.disable_balance_check = true;
    evm.env.cfg.disable_block_gas_limit = true;
    evm.env.cfg.memory_limit = u64::MAX;
    evm.env.tx.transact_to = TransactTo::Call(STATEFUL_SPONGE_ADDR);

    // Init thread RNG
    let mut rng = rand::thread_rng();

    // Re-use the same memory for the input slice and tiny-keccak hash outputs.
    let mut hash_tiny: [u8; 32] = [0u8; 32];
    let mut bytes = vec![0u8; max_input_bytes];

    for i in 0..num_hashes {
        let in_slice = bytes[0..rng.gen_range(0..max_input_bytes)].as_mut();
        rng.fill(in_slice);

        hash_input_tiny(in_slice, hash_tiny.as_mut());
        let hash_evm = hash_input_evm(&mut evm, in_slice)?;

        if hash_tiny != hash_evm {
            bail!(
                "Hash mismatch at iteration {} - input: {}",
                i,
                hex::encode(bytes)
            );
        }

        pb.inc(1);
    }

    pb.finish_with_message("DONE");
    Ok(())
}

/// Deploys the stateful sponge contract to the given database.
fn deploy_contract<T: DatabaseRef>(db: &mut CacheDB<T>) -> Result<()> {
    let sponge_code = hex::decode(STATEFUL_SPONGE_BYTECODE.trim())?;

    let mut code_hash: [u8; 32] = [0u8; 32];
    hash_input_tiny(sponge_code.as_slice(), code_hash.as_mut());

    let mut acc_info = AccountInfo {
        balance: U256::ZERO,
        nonce: 0,
        code_hash: code_hash.into(),
        code: Some(Bytecode::new_raw(sponge_code.into())),
    };
    db.insert_contract(&mut acc_info);
    db.insert_account_info(STATEFUL_SPONGE_ADDR, acc_info);
    Ok(())
}
