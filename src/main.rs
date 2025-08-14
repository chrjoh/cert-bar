#![allow(dead_code, unused_variables)]
use crate::config::read_certificate_config;
use crate::{certificate::create, config::read_csr_config};
use clap::{Parser, Subcommand};

mod certificate;
mod config;

#[derive(Parser, Debug)]
#[command(name = "program", version, about = "Certificate tool", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "./certs")]
    output_dir: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create certificates
    CERT {
        /// The config file for defining the certificates to create
        #[arg(short, long, default_value = "./examples/test_ed25519.yaml")]
        config_file: String,
    },
    /// Create certificate signing requests
    CSR {
        #[arg(short, long, default_value = "./examples/test_csr.yaml")]
        config_file: String,
    },

    /// Create certificate revocation lists
    CRL {
        #[arg(short, long, default_value = "./examples/test_crl.yaml")]
        config_file: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::CERT { config_file } => {
            let flat_certs = read_certificate_config(config_file)?;
            create(flat_certs, args.output_dir)?;
            Ok(())
        }
        Commands::CSR { config_file } => {
            let flat_csrs = read_csr_config(config_file)?;
            println!("Not implemented yet");
            Ok(())
        }
        Commands::CRL { config_file } => {
            println!("Not implemented yet");
            Ok(())
        }
    }
}
