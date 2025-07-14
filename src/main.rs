#![allow(dead_code)]
use crate::config::read_config;
use crate::generate::create;

mod config;
mod generate;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flat_certs = read_config("./examples/test_file.yaml")?;
    create(flat_certs)?;
    Ok(())
}
