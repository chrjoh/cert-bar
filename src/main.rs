#![allow(dead_code)]
use crate::config::read_config;
use crate::generate::create;
use clap::Parser;

mod config;
mod generate;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// the config file for defining the certifcates to create
    #[arg(
        short,
        long,
        default_value_t = String::from("./examples/test_ed25519.yaml"))]
    config_file: String,
    /// directory to store the created certificates and keys
    #[arg(short, long,default_value_t = String::from("./certs"))]
    outputh_dir: String,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let flat_certs = read_config(args.config_file)?;
    create(flat_certs, args.outputh_dir)?;
    Ok(())
}
