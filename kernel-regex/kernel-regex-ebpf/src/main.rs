#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static TRANSITIONS: HashMap<u32, u32> = HashMap::with_max_entries(10000, 0);
#[map]
static ACCEPT_STATES: HashMap<u32, u8> = HashMap::with_max_entries(32, 0);

const START_STATE: u32 = 0;
const MAX_PAYLOAD: usize = 1024;

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn is_accept(state: u32) -> bool {
    let index = state / 32;
    match unsafe { ACCEPT_STATES.get(index) } {
        None => false,
        Some(word) => (word >> (state % 32)) & 1 == 1,
    }
}

#[xdp]
pub fn kernel_regex(ctx: XdpContext) -> u32 {
    match try_kernel_regex(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn ip_to_str(ip_bytes: [u8; 4]) -> ([u8; 15], usize) {
    let mut buf = [0u8; 15]; // max length of an IP string "255.255.255.255"
    let mut pos = 0;

    for (i, &octet) in ip_bytes.iter().enumerate() {
        // write the octet digits
        if octet >= 100 {
            buf[pos] = b'0' + (octet / 100);
            pos += 1;
            buf[pos] = b'0' + (octet % 100 / 10);
            pos += 1;
        } else if octet >= 10 {
            buf[pos] = b'0' + (octet / 10);
            pos += 1;
        }
        buf[pos] = b'0' + (octet % 10);
        pos += 1;

        // write dot separator except after last octet
        if i < 3 {
            buf[pos] = b'.';
            pos += 1;
        }
    }

    (buf, pos)
}

fn try_kernel_regex(ctx: &XdpContext) -> Result<u32, ()> {
    // parse ethernet header
    let eth = unsafe { &*ptr_at::<EthHdr>(ctx, 0)? };
    if eth.ether_type != EtherType::Ipv4.into() {
        return Ok(xdp_action::XDP_PASS);
    }

    // parse IPv4 header
    let ip = unsafe { &*ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN)? };

    let src_ip = u32::from_be_bytes(ip.src_addr).to_be_bytes();
    let (ip_str, ip_len) = ip_to_str(src_ip);

    let mut state = START_STATE;
    for &byte in &ip_str[..ip_len] {
        let key = (state << 8) | (byte as u32);
        match unsafe { TRANSITIONS.get(&key) } {
            None => return Ok(xdp_action::XDP_PASS),
            Some(&next) => state = next,
        }
    }

    if is_accept(state) {
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

// fn try_kernel_regex(ctx: XdpContext) -> Result<u32, ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();

//     let mut state = START_STATE;

//     for i in 0..MAX_PAYLOAD {
//         let byte_ptr = (start + i) as *const u8;

//         // bounds check required by verifier
//         if byte_ptr as usize + 1 > end {
//             break;
//         }

//         let byte = unsafe { *byte_ptr } as u32;
//         let key = (state << 8) | byte;

//         match unsafe { TRANSITIONS.get(&key) } {
//             None => return Ok(xdp_action::XDP_PASS), // dead state
//             Some(&next_state) => state = next_state,
//         }
//     }

//     if is_accept(state) {
//         info!(&ctx, "match");
//         Ok(xdp_action::XDP_DROP) 
//     } else {
//         Ok(xdp_action::XDP_PASS)
//     }
// }

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
