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
const GIT_HOMEPAGE: &str = "https://github.com/rink1969/cita_ng_tools";

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
    /// Sets grpc port of kms service.
    #[clap(short = "k", long = "kms_port", default_value = "50005")]
    kms_port: String,
    /// Sets grpc port of controller service.
    #[clap(short = "c", long = "controller_port", default_value = "50004")]
    controller_port: String,
    /// Sets thread number of send tx.
    #[clap(short = "t", long = "thread_num", default_value = "4")]
    thread_num: String,
    /// Sets number of tx per thread to send.
    #[clap(short = "n", long = "tx_num_per_thread", default_value = "1000")]
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
            log4rs::init_file("send-tx-log4rs.yaml", Default::default()).unwrap();
            info!("grpc port of kms service: {}", opts.kms_port);
            info!("grpc port of controller service: {}", opts.controller_port);
            info!("thread number to send tx: {}", opts.thread_num);
            info!("tx number per thread to send: {}", opts.tx_num_per_thread);
            run(opts);
        }
    }
}

use cita_ng_proto::blockchain::{Transaction, UnverifiedTransaction, Witness};
use cita_ng_proto::common::Hash;
use cita_ng_proto::controller::{
    raw_transaction::Tx, rpc_service_client::RpcServiceClient, BlockNumber, Flag, RawTransaction,
};
use cita_ng_proto::kms::{
    kms_service_client::KmsServiceClient, GenerateKeyPairRequest, HashDateRequest,
    SignMessageRequest,
};
use prost::Message;
use rand::Rng;
use tonic::Request;
use std::time::Duration;

fn build_tx(data: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300000,
        valid_until_block: 80,
        data,
        value: vec![0u8; 32],
        chain_id: vec![0u8; 32],
    }
}

fn send_tx(
    address: Vec<u8>,
    key_id: u64,
    kms_port: String,
    controller_port: String,
    tx_num_per_thread: u64,
) -> Vec<Vec<u8>> {
    let mut rt = Runtime::new().unwrap();

    let kms_addr = format!("http://127.0.0.1:{}", kms_port);
    let controller_addr = format!("http://127.0.0.1:{}", controller_port);

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

        let tx = build_tx(data);

        // calc tx hash
        let mut tx_bytes = Vec::new();
        tx.encode(&mut tx_bytes).unwrap();
        let request = HashDateRequest {
            key_id,
            data: tx_bytes,
        };
        let ret = rt.block_on(kms_client.hash_date(request)).unwrap();
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
    let kms_port = opts.kms_port;
    let controller_port = opts.controller_port;

    let mut thread_handlers = Vec::new();

    let mut rt = Runtime::new().unwrap();

    let kms_addr = format!("http://127.0.0.1:{}", kms_port.clone());
    let controller_addr = format!("http://127.0.0.1:{}", controller_port.clone());

    let mut kms_client = rt.block_on(KmsServiceClient::connect(kms_addr)).unwrap();
    let mut rpc_client = rt
        .block_on(RpcServiceClient::connect(controller_addr))
        .unwrap();

    // generate_key_pair for sign tx
    let request = Request::new(GenerateKeyPairRequest {
        crypt_type: 1,
        description: "test".to_owned(),
    });
    let ret = rt.block_on(kms_client.generate_key_pair(request)).unwrap();
    let response = ret.into_inner();
    let key_id = response.key_id;
    let address = response.address;

    info!("key id is {}", key_id);

    // get block number
    let request = Request::new(Flag { flag: false });
    let ret = rt.block_on(rpc_client.get_block_number(request)).unwrap();
    let start_block_number = ret.into_inner().block_number;
    info!("block_number is {} before start", start_block_number);

    info!("start send tx {} with {} thread", total_tx, thread_num);
    for _ in 0..thread_num {
        let kms_port = kms_port.clone();
        let address = address.clone();
        let controller_port = controller_port.clone();
        let handler = thread::spawn(move || {
            send_tx(
                address.clone(),
                key_id,
                kms_port.clone(),
                controller_port.clone(),
                tx_num_per_thread,
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

    // get block number
    let request = Request::new(Flag { flag: false });
    let ret = rt.block_on(rpc_client.get_block_number(request)).unwrap();
    let end_block_number = ret.into_inner().block_number;
    info!("block_number is {} after start", end_block_number);

    for hash in all_hash_list {
        // get transaction by hash
        let request = Request::new(Hash { hash });
        let ret = rt.block_on(rpc_client.get_transaction(request)).unwrap();
        let raw_tx = ret.into_inner();
        info!("raw_tx {:?}", raw_tx);
    }

    info!("wait 100s ...");
    thread::sleep(Duration::new(100, 0));

    for h in start_block_number..(end_block_number + 2) {
        // get block by height
        let request = Request::new(BlockNumber { block_number: h });
        let ret = rt
            .block_on(rpc_client.get_block_by_number(request))
            .unwrap();
        let block = ret.into_inner();
        info!("height {} block {:?}", h, block);
    }
}
