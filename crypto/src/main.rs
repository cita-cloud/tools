use clap::Clap;

/// network service
#[derive(Clap)]
#[clap(version = "0.1.0", author = "Yieazy")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// print information from git
    #[clap(name = "sign")]
    Signature(SigConfig),
}

#[derive(Clap, Clone)]
struct SigConfig {
    /// Sets private key to sign.
    #[clap(short = 'p', long = "private_key")]
    private_key: String,
    /// content to be signed
    #[clap(short = 'c', long = "content")]
    content: String,
    /// signature algorithm
    #[clap(short = 'a', long = "algorithm", default_value = "sm2")]
    algorithm: String,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Signature(config) => {
            let key_pair = efficient_sm2::KeyPair::new(&hex::decode(&config.private_key).unwrap()).unwrap();
            let signature = key_pair.sign(&hex::decode(&config.content).unwrap()).unwrap();
            println!("{}{}", hex::encode(signature.r()), hex::encode(signature.s()));
        }
    }
}
