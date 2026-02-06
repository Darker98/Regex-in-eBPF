use axum::{routing::post, Json, Router};
use aya::{maps::Array, Bpf};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

const REGEX_PATTERN: &str = r"/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/";

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

fn attach_xdp_program() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf"
    )))?;

    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = bpf.program_mut("ebpf").unwrap().try_into()?;
    program.load()?;
  
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    Ok(())
}

fn upload_regex_to_ebpf() -> Result<> {
    // Load algorithm map 
    let mut algorithm_map: Array<_, [u8; 64]> = match bpf_lock.map_mut("ALGORITHM_MAP") {
        Ok(m) => match m.try_into() {
            Ok(arr) => arr,
            Err(e) => return Err((format!("map try_into error: {}", e))),
        },
        Err(e) => return Err((format!("map error: {}", e))),
    };

    let mut pattern_buf = [0u8; 64];
    let bytes = REGEX_PATTERN.as_bytes();
    let copy_len = bytes.len().min(63);
    pattern_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

    if let Err(e) = algorithm_map.set(0, pattern_buf, 0) {
        return Err((format!("failed to set pattern: {}", e)));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Attach XDP program to the specified interface
    match attach_xdp_program() {
        Ok(_) => println!("XDP program attached successfully"),
        Err(e) => eprintln!("Error attaching XDP program: {}", e),
    }

    // Attempt to upload regex pattern to eBPF map at startup
    match upload_regex_to_ebpf() {
        Ok(_) => println!("Uploaded regex pattern to eBPF map successfully"),
        Err(e) => eprintln!("Error uploading regex to eBPF: {}", e),
    }

    let app = Router::new()
        .route("/match", post(match_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    println!("Kernel XDP match endpoint listening on http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
