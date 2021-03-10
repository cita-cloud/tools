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
            info!("grpc address of kms service: {}", opts.kms_address);
            info!("grpc address of controller service: {}", opts.kms_address);
            run(opts);
        }
    }
}

use cita_cloud_proto::blockchain::{
    Transaction, UnverifiedTransaction, UnverifiedUtxoTransaction, UtxoTransaction, Witness,
};
use cita_cloud_proto::common::Empty;
use cita_cloud_proto::controller::{
    raw_transaction::Tx, rpc_service_client::RpcServiceClient, Flag, RawTransaction, SystemConfig,
};
use cita_cloud_proto::kms::{
    kms_service_client::KmsServiceClient, GenerateKeyPairRequest, HashDataRequest,
    SignMessageRequest,
};
use prost::Message;
use tonic::Request;

fn build_utxo_tx(sys_config: SystemConfig) -> UtxoTransaction {
    UtxoTransaction {
        version: sys_config.version,
        pre_tx_hash: sys_config.admin_pre_hash,
        output: vec![1u8; 21],
        lock_id: 1_002,
    }
}

fn invalid_version_utxo_tx(sys_config: SystemConfig) -> UtxoTransaction {
    UtxoTransaction {
        version: sys_config.version + 1,
        pre_tx_hash: sys_config.admin_pre_hash,
        output: vec![1u8; 21],
        lock_id: 1_002,
    }
}

fn invalid_lock_id_utxo_tx(sys_config: SystemConfig) -> UtxoTransaction {
    UtxoTransaction {
        version: sys_config.version,
        pre_tx_hash: sys_config.admin_pre_hash,
        output: vec![1u8; 21],
        lock_id: 1_005,
    }
}

fn invalid_pre_hash_utxo_tx(sys_config: SystemConfig) -> UtxoTransaction {
    UtxoTransaction {
        version: sys_config.version,
        pre_tx_hash: vec![0u8],
        output: vec![2u8; 21],
        lock_id: 1_002,
    }
}

fn send_utxo_tx(
    address: Vec<u8>,
    key_id: u64,
    kms_address: String,
    controller_address: String,
    tx: UtxoTransaction,
) -> String {
    let rt = Runtime::new().unwrap();

    let kms_addr = format!("http://{}", kms_address);
    let controller_addr = format!("http://{}", controller_address);

    let mut kms_client = rt.block_on(KmsServiceClient::connect(kms_addr)).unwrap();
    let mut rpc_client = rt
        .block_on(RpcServiceClient::connect(controller_addr))
        .unwrap();

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
        sender: address,
    };

    let unverified_tx = UnverifiedUtxoTransaction {
        transaction: Some(tx),
        transaction_hash: tx_hash,
        witnesses: vec![witness],
    };

    let raw_tx = RawTransaction {
        tx: Some(Tx::UtxoTx(unverified_tx)),
    };

    let ret = rt.block_on(rpc_client.send_raw_transaction(raw_tx));
    match ret {
        Ok(response) => {
            info!("tx hash {:?}", response.into_inner().hash);
            "".to_owned()
        }
        Err(status) => {
            info!("err {}", status.message());
            status.message().to_owned()
        }
    }
}

fn build_tx(start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 80,
        data: vec![],
        value: vec![0u8; 32],
        chain_id,
    }
}

fn invalid_version_tx(start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 80,
        data: vec![],
        value: vec![0u8; 32],
        chain_id,
    }
}

fn invalid_nonce_tx(start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "1testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 80,
        data: vec![],
        value: vec![0u8; 32],
        chain_id,
    }
}

fn invalid_vub_tx1(start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number,
        data: vec![],
        value: vec![0u8; 32],
        chain_id,
    }
}

fn invalid_vub_tx2(start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 200,
        data: vec![],
        value: vec![0u8; 32],
        chain_id,
    }
}

fn invalid_value_tx(start_block_number: u64, chain_id: Vec<u8>) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 80,
        data: vec![],
        value: vec![0u8; 31],
        chain_id,
    }
}

fn invalid_chain_id_tx(start_block_number: u64) -> Transaction {
    Transaction {
        version: 0,
        to: vec![1u8; 21],
        nonce: "test".to_owned(),
        quota: 300_000,
        valid_until_block: start_block_number + 80,
        data: vec![],
        value: vec![0u8; 32],
        chain_id: vec![0u8; 31],
    }
}

fn send_tx(
    address: Vec<u8>,
    key_id: u64,
    kms_address: String,
    controller_address: String,
    tx: Transaction,
) -> String {
    let rt = Runtime::new().unwrap();

    let kms_addr = format!("http://{}", kms_address);
    let controller_addr = format!("http://{}", controller_address);

    let mut kms_client = rt.block_on(KmsServiceClient::connect(kms_addr)).unwrap();
    let mut rpc_client = rt
        .block_on(RpcServiceClient::connect(controller_addr))
        .unwrap();

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
        sender: address,
    };

    let unverified_tx = UnverifiedTransaction {
        transaction: Some(tx),
        transaction_hash: tx_hash,
        witness: Some(witness),
    };

    let raw_tx = RawTransaction {
        tx: Some(Tx::NormalTx(unverified_tx)),
    };

    let ret = rt.block_on(rpc_client.send_raw_transaction(raw_tx));
    match ret {
        Ok(response) => {
            info!("tx hash {:?}", response.into_inner().hash);
            "".to_owned()
        }
        Err(status) => {
            info!("err {}", status.message());
            status.message().to_owned()
        }
    }
}

fn run(opts: RunOpts) {
    let kms_address = opts.kms_address;
    let controller_address = opts.controller_address;

    let rt = Runtime::new().unwrap();

    let kms_addr = format!("http://{}", kms_address.clone());
    let controller_addr = format!("http://{}", controller_address.clone());

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

    // get block number
    let request = Request::new(Flag { flag: false });
    let ret = rt.block_on(rpc_client.get_block_number(request)).unwrap();
    let start_block_number = ret.into_inner().block_number;
    info!("block_number is {} before start", start_block_number);

    // get system config
    let request = Request::new(Empty {});
    let ret = rt.block_on(rpc_client.get_system_config(request)).unwrap();
    let sys_config = ret.into_inner();
    let chain_id = sys_config.chain_id.clone();
    info!("sys_config is {:?} before start", sys_config);

    // ok
    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            build_tx(start_block_number, chain_id.clone()),
        ),
        "".to_owned()
    );

    // dup
    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            build_tx(start_block_number, chain_id.clone()),
        ),
        "dup".to_owned()
    );

    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_version_tx(start_block_number, chain_id.clone()),
        ),
        "Invalid version".to_owned()
    );

    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_nonce_tx(start_block_number, chain_id.clone()),
        ),
        "Invalid nonce".to_owned()
    );

    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_vub_tx1(start_block_number, chain_id.clone()),
        ),
        "Invalid valid_until_block".to_owned()
    );

    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_vub_tx2(start_block_number, chain_id.clone()),
        ),
        "Invalid valid_until_block".to_owned()
    );

    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_value_tx(start_block_number, chain_id.clone()),
        ),
        "Invalid value".to_owned()
    );

    assert_eq!(
        send_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_chain_id_tx(start_block_number),
        ),
        "Invalid chain_id".to_owned()
    );

    assert_eq!(
        send_utxo_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            build_utxo_tx(sys_config.clone()),
        ),
        "".to_owned()
    );

    assert_eq!(
        send_utxo_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_version_utxo_tx(sys_config.clone()),
        ),
        "Invalid version".to_owned()
    );

    assert_eq!(
        send_utxo_tx(
            address.clone(),
            key_id,
            kms_address.clone(),
            controller_address.clone(),
            invalid_lock_id_utxo_tx(sys_config.clone()),
        ),
        "Invalid lock_id".to_owned()
    );

    assert_eq!(
        send_utxo_tx(
            address,
            key_id,
            kms_address,
            controller_address,
            invalid_pre_hash_utxo_tx(sys_config),
        ),
        "Invalid pre_tx_hash".to_owned()
    );
}
