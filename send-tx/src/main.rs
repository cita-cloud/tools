// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::Clap;
use git_version::git_version;
use log::info;
use std::thread;
use tokio::runtime::Runtime;

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/tools";

/// network service
#[derive(Clap)]
#[clap(version = "0.1.0", author = "Rivtower Technologies.")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// print information from git
    #[clap(name = "git")]
    GitInfo,
    /// run this service
    #[clap(name = "run")]
    Run(RunOpts),
}

/// A subcommand for run
#[derive(Clap)]
struct RunOpts {
    /// Sets grpc address of kms service.
    #[clap(short = 'k', long = "kms_address", default_value = "localhost:50005")]
    kms_address: String,
    /// Sets grpc address of controller service.
    #[clap(
        short = 'c',
        long = "controller_address",
        default_value = "localhost:50004"
    )]
    controller_address: String,
    /// Sets thread number of send tx.
    #[clap(short = 't', long = "thread_num", default_value = "4")]
    thread_num: String,
    /// Sets number of tx per thread to send.
    #[clap(short = 'n', long = "tx_num_per_thread", default_value = "1000")]
    tx_num_per_thread: String,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::GitInfo => {
            println!("git version: {}", GIT_VERSION);
            println!("homepage: {}", GIT_HOMEPAGE);
        }
        SubCommand::Run(opts) => {
            // init log4rs
            log4rs::init_file("tools-log4rs.yaml", Default::default()).unwrap();
            info!("grpc port of kms service: {}", opts.kms_address);
            info!(
                "grpc port of controller service: {}",
                opts.controller_address
            );
            info!("thread number to send tx: {}", opts.thread_num);
            info!("tx number per thread to send: {}", opts.tx_num_per_thread);
            run(opts);
        }
    }
}

use cita_cloud_proto::blockchain::{Transaction, UnverifiedTransaction, Witness};
use cita_cloud_proto::common::{Empty, Hash};
use cita_cloud_proto::controller::raw_transaction::Tx::NormalTx;
use cita_cloud_proto::controller::{
    raw_transaction::Tx, rpc_service_client::RpcServiceClient, BlockNumber, Flag, RawTransaction,
};
use cita_cloud_proto::kms::{
    kms_service_client::KmsServiceClient, GenerateKeyPairRequest, HashDataRequest,
    SignMessageRequest,
};
use prost::Message;
use rand::Rng;
use std::io::Write;
use std::time::Duration;
use tonic::Request;

fn build_tx(data: Vec<u8>, start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 20],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 99,
        data,
        value: vec![0u8; 32],
        chain_id,
    }
}

fn send_tx(
    address: Vec<u8>,
    key_id: u64,
    kms_address: String,
    controller_address: String,
    tx_num_per_thread: u64,
    start_block_number: u64,
    chain_id: Vec<u8>,
) -> Vec<Vec<u8>> {
    let rt = Runtime::new().unwrap();

    let kms_addr = format!("http://{}", kms_address);
    let controller_addr = format!("http://{}", controller_address);

    let mut kms_client = rt.block_on(KmsServiceClient::connect(kms_addr)).unwrap();
    let mut rpc_client = rt
        .block_on(RpcServiceClient::connect(controller_addr))
        .unwrap();

    let mut tx_hash_list = Vec::new();

    for _ in 0..tx_num_per_thread {
        let mut data = Vec::new();
        for _ in 0..32 {
            let v: u8 = rand::thread_rng().gen();
            data.push(v);
        }

        let tx = build_tx(data, start_block_number, chain_id.clone());

        // calc tx hash
        let mut tx_bytes = Vec::new();
        tx.encode(&mut tx_bytes).unwrap();
        let request = HashDataRequest { data: tx_bytes };
        let ret = rt.block_on(kms_client.hash_data(request)).unwrap();
        let tx_hash = ret.into_inner().hash;

        // sign tx hash
        let request = Request::new(SignMessageRequest {
            key_id,
            msg: tx_hash.clone(),
        });
        let ret = rt.block_on(kms_client.sign_message(request)).unwrap();
        let signature = ret.into_inner().signature;

        let witness = Witness {
            signature,
            sender: address.clone(),
        };

        let unverified_tx = UnverifiedTransaction {
            transaction: Some(tx),
            transaction_hash: tx_hash.clone(),
            witness: Some(witness),
        };

        let raw_tx = RawTransaction {
            tx: Some(Tx::NormalTx(unverified_tx)),
        };

        let ret = rt
            .block_on(rpc_client.send_raw_transaction(raw_tx))
            .unwrap();
        let hash = ret.into_inner().hash;
        assert_eq!(hash, tx_hash);
        tx_hash_list.push(hash);
    }
    tx_hash_list
}

fn run(opts: RunOpts) {
    let thread_num = opts.thread_num.parse::<u64>().unwrap();
    let tx_num_per_thread = opts.tx_num_per_thread.parse::<u64>().unwrap();
    let total_tx = thread_num * tx_num_per_thread;
    let kms_address = opts.kms_address;
    let controller_address = opts.controller_address;

    let mut thread_handlers = Vec::new();

    let rt = Runtime::new().unwrap();

    let kms_addr = format!("http://{}", kms_address);
    let controller_addr = format!("http://{}", controller_address);

    let mut kms_client = rt.block_on(KmsServiceClient::connect(kms_addr)).unwrap();
    let mut rpc_client = rt
        .block_on(RpcServiceClient::connect(controller_addr))
        .unwrap();

    // generate_key_pair for sign tx
    let request = Request::new(GenerateKeyPairRequest {
        description: "test".to_owned(),
    });
    let ret = rt.block_on(kms_client.generate_key_pair(request)).unwrap();
    let response = ret.into_inner();
    let key_id = response.key_id;
    let address = response.address;

    info!("key id is {}", key_id);

    // get system config
    let request = Request::new(Empty {});
    let ret = rt.block_on(rpc_client.get_system_config(request)).unwrap();
    let sys_config = ret.into_inner();
    let chain_id = sys_config.chain_id;

    // get block number
    let request = Request::new(Flag { flag: false });
    let ret = rt.block_on(rpc_client.get_block_number(request)).unwrap();
    let mut start_block_number = ret.into_inner().block_number;
    info!("block_number is {} before start", start_block_number);

    info!("start send tx {} with {} thread", total_tx, thread_num);
    for _ in 0..thread_num {
        let kms_address = kms_address.clone();
        let address = address.clone();
        let controller_address = controller_address.clone();
        let chain_id = chain_id.clone();
        let handler = thread::spawn(move || {
            send_tx(
                address.clone(),
                key_id,
                kms_address.clone(),
                controller_address.clone(),
                tx_num_per_thread,
                start_block_number,
                chain_id,
            )
        });
        thread_handlers.push(handler);
    }

    let mut all_hash_list = Vec::new();
    for handler in thread_handlers {
        let mut tx_hash_list = handler.join().unwrap();
        all_hash_list.append(&mut tx_hash_list);
    }

    assert_eq!(all_hash_list.len() as u64, total_tx);

    let _ = std::fs::remove_file("tx_hash_list.txt");
    let mut file = std::fs::File::create("tx_hash_list.txt").expect("Can't open tx_hash_list.txt");

    for hash in all_hash_list.as_slice() {
        let tx_hash_hex = hex::encode(hash);
        let tx_hash_base64 = base64::encode(hash);
        file.write_all(format!("{} {}\n", tx_hash_hex, tx_hash_base64).as_bytes())
            .expect("write failed");
    }

    for hash in all_hash_list {
        // get transaction by hash
        let request = Request::new(Hash { hash });
        let ret = rt.block_on(rpc_client.get_transaction(request)).unwrap();
        let raw_tx = ret.into_inner();
        let nonce = match raw_tx.tx.unwrap() {
            NormalTx(tx) => tx.transaction.unwrap().nonce,
            _ => {
                panic!("there are no utxo tx");
            }
        };
        assert_eq!(&nonce, "test");
    }

    let mut total_finalized_tx = 0;
    loop {
        thread::sleep(Duration::new(10, 0));

        // get block number
        let request = Request::new(Flag { flag: false });
        let ret = rt.block_on(rpc_client.get_block_number(request)).unwrap();
        let end_block_number = ret.into_inner().block_number;

        for h in start_block_number..end_block_number {
            // get block by height
            let request = Request::new(BlockNumber { block_number: h });
            let ret = rt
                .block_on(rpc_client.get_block_by_number(request))
                .unwrap();
            let block = ret.into_inner();
            let block_tx_size = block.body.unwrap().tx_hashes.len();
            total_finalized_tx += block_tx_size;
            info!(
                "height {} block include {} txs, total finalized tx {}",
                h, block_tx_size, total_finalized_tx
            );
        }

        if total_finalized_tx as u64 == total_tx {
            break;
        }

        start_block_number = end_block_number;
    }
}
