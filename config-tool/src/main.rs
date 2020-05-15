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
    #[clap(short = "c", long = "chain_name", default_value = "test-chain")]
    chain_name: String,
    /// Sets node list of the chain.
    #[clap(
        short = "n",
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
    pub privkey_path: String,
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

pub const SERVICE_LIST: [&str; 7] = [
    "config",
    "controller",
    "executor",
    "kms",
    "network",
    "pos",
    "storage",
];

fn gen_log4rs_config(index: usize, node_path: &Path) -> bool {
    for service_name in SERVICE_LIST.iter() {
        let path = node_path.join(format!("{}-log4rs.yaml", service_name));
        let ret = File::create(path);
        if let Err(e) = ret {
            println!(
                "create node{} service {} log4rs config file failed: {:?}",
                index, service_name, e
            );
            return false;
        }
        let mut f = ret.unwrap();
        let content = format!(
            "# Scan this file for changes every 30 seconds
refresh_rate: 30 seconds

appenders:
  # An appender named \"stdout\" that writes to stdout
  stdout:
    kind: console

  journey-service:
    kind: rolling_file
    path: \"logs/{}-service.log\"
    policy:
      # Identifies which policy is to be used. If no kind is specified, it will
      # default to \"compound\".
      kind: compound
      # The remainder of the configuration is passed along to the policy's
      # deserializer, and will vary based on the kind of policy.
      trigger:
        kind: size
        limit: 1mb
      roller:
        kind: fixed_window
        base: 1
        count: 5
        pattern: \"logs/{}-service.{{}}.gz\"

# Set the default logging level and attach the default appender to the root
root:
  level: info
  appenders:
    - journey-service
",
            service_name, service_name
        );
        f.write_all(content.as_bytes()).unwrap();
    }
    true
}

fn gen_sh(root_path: &Path) -> bool {
    let run_sh_path = root_path.join("run.sh");
    let ret = File::create(run_sh_path);
    if let Err(e) = ret {
        println!("create run sh file failed: {:?}", e);
        return false;
    }
    let mut f = ret.unwrap();
    f.write_all(
        "
#!/bin/bash
set -e

n=$1
echo \"node number is $n\"
cd node$n

config_port=$[49999+n*1000]
echo \"config_port is $config_port\"
networ_port=$[config_port+1]
echo \"networ_port is $networ_port\"
consensus_port=$[config_port+2]
echo \"consensus_port is $consensus_port\"
executor_port=$[config_port+3]
echo \"executor_port is $executor_port\"
storage_port=$[config_port+4]
echo \"storage_port is $storage_port\"
controller_port=$[config_port+5]
echo \"controller_port is $controller_port\"
kms_port=$[config_port+6]
echo \"kms_port is $kms_port\"

rm -rf ./logs
../bin/cita_ng_config run -p $config_port &
../bin/cita_ng_network run -c $config_port -p $networ_port &
../bin/cita_ng_storage run -c $config_port -p $storage_port &
../bin/cita_ng_pos run -c $config_port -p $consensus_port &
../bin/cita_ng_executor run -c $config_port -p $executor_port &
../bin/cita_ng_controller run -c $config_port -p $controller_port &
#../bin/cita_kms run -c $config_port -p $kms_port &
"
        .as_bytes(),
    )
    .unwrap();

    let stop_sh_path = root_path.join("stop.sh");
    let ret = File::create(stop_sh_path);
    if let Err(e) = ret {
        println!("create run sh file failed: {:?}", e);
        return false;
    }
    let mut f = ret.unwrap();
    f.write_all(
        "
#!/bin/bash
killall cita_ng_config
killall cita_ng_network
killall cita_ng_storage
killall cita_ng_pos
killall cita_ng_executor
killall cita_ng_controller
killall cita_kms
"
        .as_bytes(),
    )
    .unwrap();
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
            privkey_path: "privkey".to_owned(),
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

    // create bin dir
    let bin_path = root_path.join("bin");
    if let Err(e) = create_dir(bin_path) {
        println!("create bin dir failed: {:?}", e);
        return;
    }

    // generate run.sh and stop.sh
    if !gen_sh(&root_path) {
        return;
    }

    for (index, net_config) in net_config_list.into_iter().enumerate() {
        let node_path = root_path.join(format!("node{}", index));
        if let Err(e) = create_dir(&node_path) {
            println!("create node{} dir failed: {:?}", index, e);
            return;
        }

        let config_dir = node_path.join("config_dir");
        if let Err(e) = create_dir(&config_dir) {
            println!("create node{} config_dir failed: {:?}", index, e);
            return;
        }

        let net_config_path = config_dir.join("network.conf");
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

        if !gen_log4rs_config(index, &node_path) {
            return;
        }
    }
    println!("generate all config files success!");
    println!(
        "build all {:?} service and copy bin into ./{}/bin/",
        SERVICE_LIST, opts.chain_name
    );
    println!("then run following command:");
    println!("cd {}", opts.chain_name);
    println!("chmod +x ./run.sh ./stop.sh");
}
