use cita_cloud_proto::executor::executor_service_client::ExecutorServiceClient;
use cita_cloud_proto::executor::CallRequest;
use clap::Clap;
use log::info;
use tokio::runtime::Runtime;
use tonic::Request;

/// A subcommand for call
#[derive(Clap, Clone)]
pub struct CallOpts {
    /// from address
    #[clap(short = 'f', long = "from_address", default_value = "none")]
    pub from: String,
    /// from address
    #[clap(short = 't', long = "to_address", default_value = "none")]
    pub to: String,
    /// invoke data
    #[clap(short = 'd', long = "data", default_value = "none")]
    pub data: String,
    /// Sets grpc address of executor service.
    #[clap(
        short = 'e',
        long = "executor_address",
        default_value = "localhost:50002"
    )]
    pub executor_address: String,
}

pub fn call_tx(opts: CallOpts) {
    let rt = Runtime::new().unwrap();

    let executor_address = opts.executor_address.clone();
    let executor_addr = format!("http://{}", executor_address);
    let mut executor_client = rt
        .block_on(ExecutorServiceClient::connect(executor_addr))
        .unwrap();

    let from = {
        if opts.from.as_str() == "none" {
            vec![0; 20]
        } else {
            hex::decode(opts.from).unwrap()
        }
    };

    let to = {
        if opts.to.as_str() == "none" {
            // maybe just create contract, reserve
            Vec::new()
        } else {
            hex::decode(opts.to).unwrap()
        }
    };

    let request = Request::new(CallRequest {
        from,
        to,
        method: hex::decode(opts.data).unwrap(),
        args: Vec::new(),
    });
    let ret = rt.block_on(executor_client.call(request)).unwrap();

    info!("call result: {}", hex::encode(ret.into_inner().value));
}
