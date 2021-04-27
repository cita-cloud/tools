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
    /// enable emergency_brake
    #[clap(name = "enable")]
    Enable(RunOpts),
    /// disable emergency_brake
    #[clap(name = "disable")]
    Disable(RunOpts),
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
    #[clap(short = 'i', long = "admin_key_id")]
    admin_key_id: u64,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::GitInfo => {
            println!("git version: {}", GIT_VERSION);
            println!("homepage: {}", GIT_HOMEPAGE);
        }
        SubCommand::Enable(opts) => {
            // init log4rs
            log4rs::init_file("tools-log4rs.yaml", Default::default()).unwrap();
            info!("grpc address of kms service: {}", opts.kms_address);
            info!(
                "grpc address of controller service: {}",
                opts.controller_address
            );
            info!("admin key_id: {}", opts.admin_key_id);
            run(opts, true);
        }
        SubCommand::Disable(opts) => {
            // init log4rs
            log4rs::init_file("tools-log4rs.yaml", Default::default()).unwrap();
            info!("grpc address of kms service: {}", opts.kms_address);
            info!(
                "grpc address of controller service: {}",
                opts.controller_address
            );
            info!("admin key_id: {}", opts.admin_key_id);
            run(opts, false);
        }
    }
}

use cita_cloud_proto::blockchain::{UnverifiedUtxoTransaction, UtxoTransaction, Witness};
use cita_cloud_proto::common::{Empty, Hash};
use cita_cloud_proto::controller::{
    raw_transaction::Tx, rpc_service_client::RpcServiceClient, Flag, RawTransaction, SystemConfig,
};
use cita_cloud_proto::kms::{
    kms_service_client::KmsServiceClient, HashDataRequest, SignMessageRequest,
};
use prost::Message;
use std::thread;
use std::time::Duration;
use tonic::Request;

fn build_utxo_tx(sys_config: SystemConfig, output: Vec<u8>) -> UtxoTransaction {
    UtxoTransaction {
        version: sys_config.version,
        pre_tx_hash: sys_config.emergency_brake_pre_hash,
        output,
        lock_id: 1_005,
    }
}

fn send_utxo_tx(
    address: Vec<u8>,
    key_id: u64,
    kms_address: String,
    controller_address: String,
    tx: UtxoTransaction,
) -> Option<Vec<u8>> {
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
        Ok(response) => Some(response.into_inner().hash),
        Err(status) => {
            info!("err {}", status.message());
            None
        }
    }
}

fn run(opts: RunOpts, is_emergency_brake: bool) {
    let kms_address = opts.kms_address;
    let controller_address = opts.controller_address;
    let admin_key_id = opts.admin_key_id;

    let rt = Runtime::new().unwrap();

    let controller_addr = format!("http://{}", controller_address);
    let mut rpc_client = rt
        .block_on(RpcServiceClient::connect(controller_addr))
        .unwrap();

    // get block number
    let request = Request::new(Flag { flag: false });
    let ret = rt.block_on(rpc_client.get_block_number(request)).unwrap();
    let start_block_number = ret.into_inner().block_number;
    info!("block_number is {} before start", start_block_number);

    // get system config
    let request = Request::new(Empty {});
    let ret = rt.block_on(rpc_client.get_system_config(request)).unwrap();
    let sys_config = ret.into_inner();
    let admin = sys_config.admin.clone();
    info!("sys_config is {:?} before", sys_config);

    let ret = if is_emergency_brake {
        send_utxo_tx(
            admin,
            admin_key_id,
            kms_address,
            controller_address,
            build_utxo_tx(sys_config, vec![0]),
        )
    } else {
        send_utxo_tx(
            admin,
            admin_key_id,
            kms_address,
            controller_address,
            build_utxo_tx(sys_config, vec![]),
        )
    };

    if let Some(tx_hash) = ret {
        info!("waiting for a while...");
        loop {
            thread::sleep(Duration::new(3, 0));
            let request = Request::new(Hash {
                hash: tx_hash.clone(),
            });
            let ret = rt.block_on(rpc_client.get_transaction(request));
            if let Ok(response) = ret {
                let raw_tx = response.into_inner();
                match raw_tx.tx.unwrap() {
                    Tx::NormalTx(_) => panic!("there are no normal tx"),
                    _ => {
                        info!("OK!");
                        return;
                    }
                };
            }
        }
    } else {
        info!("failed!");
    }
}
