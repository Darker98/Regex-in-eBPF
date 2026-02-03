use aya::{
    maps::Array,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use clap::Parser;
use log::info;
use std::convert::TryInto;

#[derive(Parser)]
#[command(author, version, about)]
struct Opt {
    /// Interface to attach XDP program to
    #[arg(short, long)]
    iface: String,

    /// Pattern to load into kernel map
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

    info!("Kernel-space Pattern Matching with Aya");
    info!("Interface: {}", opts.iface);
    info!("Pattern: {}", opts.pattern);

    // Load eBPF program
    let ebpf_path = opts.ebpf.unwrap_or_else(|| {
        "/usr/local/bin/xdp_pattern_match".to_string()
    });

    let mut bpf = Bpf::load_file(&ebpf_path)?;
    info!("eBPF program loaded");

    // Get algorithm map and load pattern
    let mut algorithm_map: Array<_, [u8; 64]> = bpf.map_mut("ALGORITHM_MAP")?
        .try_into()?;

    let mut pattern_buf = [0u8; 64];
    let pattern_bytes = opts.pattern.as_bytes();
    let copy_len = pattern_bytes.len().min(63);
    pattern_buf[..copy_len].copy_from_slice(&pattern_bytes[..copy_len]);

    algorithm_map.set(0, pattern_buf, 0)?;
    info!("Pattern loaded into kernel map");

    // Load XDP program
    let program: &mut Xdp = bpf.program_mut("xdp_pattern_match")
        .ok_or("No XDP program found")?
        .try_into()?;

    program.load()?;
    program.attach(&opts.iface, XdpFlags::default())?;
    info!("XDP program attached to {}", opts.iface);

    // Get results map for monitoring
    let results_map: Array<_, u32> = bpf.map("RESULTS_MAP")?
        .try_into()?;

    info!("Pattern matching active in kernel space");
    
    let mut count = 0;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Check results map for matches
        if let Ok(result) = results_map.get(0, 0) {
            if result == 1 {
                info!("Pattern match detected!");
            }
        }

        count += 1;
        if count % 10 == 0 {
            info!("Still monitoring. Kernel pattern matching active.");
        }
    }
}
