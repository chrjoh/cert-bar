use cert_bar::config::{
    read_certificate_config, read_cms_config, read_crl_config, read_csr_config,
};
use cert_bar::{certificate, cms, crl, csr};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "program", version, about = "Certificate tool", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create certificates
    Cert {
        /// The config file for defining the certificates to create
        #[arg(short, long, default_value = "./examples/test.yaml")]
        config_file: String,
        #[arg(short, long, default_value = "./certs")]
        output_dir: String,
    },
    /// Create certificate signing requests
    Csr {
        #[arg(short, long, default_value = "./examples/test_csr.yaml")]
        config_file: String,
        #[arg(short, long, default_value = "./certs")]
        output_dir: String,
    },

    /// Create certificate revocation lists
    Crl {
        #[arg(short, long, default_value = "./examples/test_crl.yaml")]
        config_file: String,
        #[arg(short, long, default_value = "./certs")]
        output_dir: String,
    },
    /// Create Cryptographic Message
    Cms {
        #[arg(short, long, default_value = "./examples/test_cms.yaml")]
        config_file: String,
        #[arg(short, long, default_value = "./cms_data")]
        output_dir: String,
    },
    /// Launch the interactive terminal UI
    #[cfg(feature = "tui")]
    Tui {
        /// Default output directory pre-filled in the generate / save prompts
        #[arg(short, long, default_value = "./")]
        output_dir: String,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Cert {
            config_file,
            output_dir,
        } => match read_certificate_config(config_file) {
            Ok(flat_certs) => match certificate::create(flat_certs, output_dir) {
                Ok(_) => println!("Created all certificates"),
                Err(e) => println!("Failed to generate all certs, with error: {}", e),
            },
            Err(e) => println!("Failed to read certificate config file with error: {}", e),
        },
        Commands::Csr {
            config_file,
            output_dir,
        } => match read_csr_config(config_file) {
            Ok(data) => {
                match csr::create_csr(data.csrs, &output_dir) {
                    Ok(_) => println!("Created all CSR"),
                    Err(e) => println!("Failed to create all CSR with error {}", e),
                }
                match csr::sign_requests(data.to_sign, &output_dir) {
                    Ok(_) => println!("Signed all requests"),
                    Err(e) => println!("Failed to sign requests with error {}", e),
                }
            }
            Err(e) => println!("Failed to read csr config file with error: {}", e),
        },
        Commands::Crl {
            config_file,
            output_dir,
        } => match read_crl_config(config_file) {
            Ok(data) => match crl::handle(data, output_dir) {
                Ok(_) => println!("Updated or created CRL"),
                Err(e) => println!("Failed to handle CRL with error {}", e),
            },
            Err(e) => println!("Failed to read crl config file with error: {}", e),
        },
        Commands::Cms {
            config_file,
            output_dir,
        } => match read_cms_config(config_file) {
            Ok(data) => match cms::handle(data, output_dir) {
                Ok(_) => println!("Created cms/pkcs7 data file"),
                Err(e) => println!("Failed to handle CMD with error {}", e),
            },
            Err(e) => println!("Failed to read Cms config file with error: {}", e),
        },
        #[cfg(feature = "tui")]
        Commands::Tui { output_dir } => match cert_bar::tui::run(output_dir) {
            // The TUI entrypoint restores the terminal via its RAII guard on
            // every path, so here we only report the outcome to stdout/stderr.
            Ok(()) => println!("Exited TUI"),
            Err(e) => eprintln!("TUI exited with error: {}", e),
        },
    }
}
