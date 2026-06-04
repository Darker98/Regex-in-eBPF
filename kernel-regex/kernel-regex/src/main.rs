use anyhow::Context as _;
use aya::{Ebpf, maps::{Array, HashMap}, programs::{Xdp, XdpFlags}};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use crate::{dfa_to_hashmap::{DfaMap, dfa_to_map}, nfa_to_dfa::nfa_to_dfa, regex_preprocessing::postfix, regex_to_nfa::build};

mod regex_to_nfa;
mod nfa_to_dfa;
mod regex_preprocessing;
mod dfa_to_hashmap;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

const REGEX_PATTERN: &str = r"192.168.100.6";

pub fn upload_regex(bpf: &mut Ebpf, regex: &str) -> Result<(), anyhow::Error> {
    let (nfa, frag) = build(regex);
    let dfa = nfa_to_dfa(&nfa, &frag);
    let dfa_map = dfa_to_map(&dfa);

    load_dfa_into_maps(bpf, &dfa_map)?;

    Ok(())
}

pub fn load_dfa_into_maps(bpf: &mut Ebpf, dfa_map: &DfaMap) -> Result<(), anyhow::Error> {
    // load transition table
    let mut transitions: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("TRANSITIONS").unwrap()
    )?;

    for (&key, &next_state) in &dfa_map.transitions {
        transitions.insert(key, next_state, 0)?;
    }

    // load accept states
    let mut accept_states: HashMap<_, u32, u8> = HashMap::try_from(
        bpf.map_mut("ACCEPT_STATES").unwrap()
    )?;

    for &state in &dfa_map.accept_states {
        accept_states.insert(state, 1u8, 0)?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-regex"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("kernel_regex").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    upload_regex(&mut ebpf, REGEX_PATTERN)?;
    
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
