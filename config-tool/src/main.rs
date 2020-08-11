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

#[derive(Clap)]
#[clap(version = "0.1.0", author = "Rivtower Technologies.")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// generate config files
    #[clap(name = "gen")]
    Gen(GenOpts),
}

/// A subcommand for generate config files.
#[derive(Clap)]
struct GenOpts {
    /// Sets name of the chain.
    #[clap(short = 'c', long = "chain_name", default_value = "test-chain")]
    chain_name: String,
    /// Sets node list of the chain.
    #[clap(
        short = 'n',
        long = "node_list",
        default_value = "127.0.0.1:40000;127.0.0.1:40001"
    )]
    node_list: String,
}

fn main() {
    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Gen(opts) => {
            println!("chain_name: {}", opts.chain_name);
            println!("node_list: {}", opts.node_list);
            run(opts);
        }
    }
}

use rand::{thread_rng, Rng};
use serde_derive::Serialize;
use std::fs::{create_dir, File};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Clone)]
pub struct NetConfig {
    pub port: u16,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PeerConfig {
    pub ip: String,
    pub port: u16,
}

fn gen_private_key(index: usize, node_path: &Path) -> bool {
    let privkey_path = node_path.join("privkey");
    let ret = File::create(privkey_path);
    if let Err(e) = ret {
        println!("create node{} net config file failed: {:?}", index, e);
        return false;
    }
    let mut f = ret.unwrap();
    let _ = f.write(b"0x").unwrap();
    for _ in 0..32 {
        let n: u8 = thread_rng().gen();
        let _ = f.write(format!("{:02x}", n).as_bytes()).unwrap();
    }
    true
}

fn run(opts: GenOpts) {
    let peers: Vec<PeerConfig> = opts
        .node_list
        .split_terminator(';')
        .map(|node_str| {
            let ip_and_port: Vec<&str> = node_str.split_terminator(':').collect();
            let ip = ip_and_port[0].to_owned();
            let port = ip_and_port[1].parse::<u16>().unwrap();
            PeerConfig { ip, port }
        })
        .collect();

    let mut net_config_list = Vec::new();
    for (index, peer) in peers.iter().enumerate() {
        let mut peers_clone = peers.clone();
        // remove current peer, left other peers
        let _ = peers_clone.remove(index);

        let net_config = NetConfig {
            port: peer.port,
            peers: peers_clone,
        };
        net_config_list.push(net_config);
    }

    // create root dir with chain name
    let root = format!("./{}", opts.chain_name);
    let root_path = Path::new(&root);
    if let Err(e) = create_dir(root_path) {
        println!("create root dir failed: {:?}", e);
        return;
    }

    for (index, net_config) in net_config_list.into_iter().enumerate() {
        let node_path = root_path.join(format!("node{}", index));
        if let Err(e) = create_dir(&node_path) {
            println!("create node{} dir failed: {:?}", index, e);
            return;
        }

        let net_config_path = node_path.join("network.conf");
        let ret = File::create(net_config_path);
        if let Err(e) = ret {
            println!("create node{} net config file failed: {:?}", index, e);
            return;
        }
        let mut f = ret.unwrap();
        f.write_all(toml::to_string(&net_config).unwrap().as_bytes())
            .unwrap();

        if !gen_private_key(index, &node_path) {
            return;
        }
    }
    println!("generate all config files success!");
}
