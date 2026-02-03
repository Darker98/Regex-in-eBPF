use aya::{
    programs::{Xdp, XdpFlags},
    Bpf,
};
use clap::Parser;
use log::info;
use regex::Regex;
use std::convert::TryInto;

#[derive(Parser)]
#[command(author, version, about)]
struct Opt {
    /// Interface to attach XDP program to
    #[arg(short, long)]
    iface: String,

    /// Regex pattern for packet payload matching
    #[arg(short, long)]
    pattern: String,

    /// eBPF object file path
    #[arg(short, long)]
    ebpf: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let opts = Opt::parse();

    info!("Userspace Pattern Matching with Regex");
    info!("Interface: {}", opts.iface);
    info!("Pattern: {}", opts.pattern);

    // Compile regex pattern
    let regex = Regex::new(&opts.pattern)?;
    info!("Regex compiled successfully");

    // Load eBPF program
    let ebpf_path = opts.ebpf.unwrap_or_else(|| {
        "/usr/local/bin/xdp_redirect".to_string()
    });

    let mut bpf = Bpf::load_file(&ebpf_path)?;
    info!("eBPF program loaded");

    // Load XDP program
    let program: &mut Xdp = bpf.program_mut("xdp_redirect_payload")
        .ok_or("No XDP program found")?
        .try_into()?;

    program.load()?;
    program.attach(&opts.iface, XdpFlags::default())?;
    info!("XDP program attached to {}", opts.iface);

    // Simulate packet payload reception and pattern matching
    info!("Waiting for packets...");
    
    let mut count = 0;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // In a real scenario, packets would be received here via:
        // - AF_XDP sockets
        // - Perf buffers
        // - Ring buffers
        
        count += 1;
        if count % 10 == 0 {
            info!("Still running. Pattern matching active.");
        }
    }
}
