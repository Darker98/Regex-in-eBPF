#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{bindings::xdp_action, macros::{map, xdp}, maps::Array, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// Map to store pattern algorithm from userspace
#[map]
static ALGORITHM_MAP: Array<[u8; 64]> = Array::with_max_entries(256, 0);

const MAX_ITERS: u32 = 1000;

// #[repr(C)]
// pub struct EthHdr {
//     pub dst_addr: [u8; 6],
//     pub src_addr: [u8; 6],
//     pub proto: u16,
// }

// #[repr(C)]
// pub struct IpHdr {
//     pub version_ihl: u8,
//     pub dscp_ecn: u8,
//     pub total_len: u16,
//     pub identification: u16,
//     pub flags_frag_offset: u16,
//     pub ttl: u8,
//     pub proto: u8,
//     pub checksum: u16,
//     pub src_addr: u32,
//     pub dst_addr: u32,
// }

// #[repr(C)]
// pub struct TcpHdr {
//     pub src_port: u16,
//     pub dst_port: u16,
//     pub seq: u32,
//     pub ack_seq: u32,
//     pub data_offset_flags: u16,
//     pub window: u16,
//     pub checksum: u16,
//     pub urgent_ptr: u16,
// }

#[repr(C)]
pub struct Payload {
    pub data: [u8; 20]
}

// // Simple substring matching function for kernel space
// #[inline]
// fn match_pattern(payload: &[u8], pattern: &[u8]) -> bool {
//     if pattern.is_empty() || pattern.len() > payload.len() {
//         return false;
//     }

//     let pattern_len = pattern.len();
//     for i in 0..=(payload.len() - pattern_len) {
//         let mut matched = true;
//         for j in 0..pattern_len {
//             if payload[i + j] != pattern[j] {
//                 matched = false;
//                 break;
//             }
//         }
//         if matched {
//             return true;
//         }
//     }
//     false
// }

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

#[xdp]
pub fn kernel_regex(ctx: XdpContext) -> u32 {
    match try_kernel_regex(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_kernel_regex(ctx: XdpContext) -> Result<u32, ()> {
    {
        // Parse Ethernet header
        let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; 
        match unsafe { (*ethhdr).ether_type() } {
            Ok(EtherType::Ipv4) => {}
            _ => return Ok(xdp_action::XDP_PASS),
        }
    }

    let ihl = {
        // Parse IP header
        let ip_hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
        match unsafe { (*ip_hdr).proto } {
            IpProto::Tcp => {}
            _ => return Ok(xdp_action::XDP_PASS),
        }
        let ihl = unsafe { (*ip_hdr).ihl() as usize * 4 };
        ihl
    };

    // Parse TCP header
    {
        let udp_hdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + ihl)?;
        match unsafe { u16::from_be_bytes((*udp_hdr).dst) } {
            4000 => {}
            _ => return Ok(xdp_action::XDP_PASS),
        }
    }
    let udp_len = 8usize;

    // Get payload
    let payload_offset = EthHdr::LEN + ihl + udp_len;
    let payload: *const Payload = ptr_at(&ctx, payload_offset)?;

    let index: u32 = 0;

    // Compare up to 64 bytes 
    let mut matched = true;

    // Loop over each byte of the pattern 
    for i in 0..20 {
        // Read the i-th byte directly from the map
        let pattern_byte = match ALGORITHM_MAP.get(index) {
            Some(buf) => buf[i],
            None => {
                matched = false;
                break;
            }
        };

        // Stop if pattern ends
        if pattern_byte == 0 {
            break;
        }

        let payload_byte = unsafe { (*payload).data[i] };

        if payload_byte != pattern_byte {
            matched = false;
            break;
        }
    }

    unsafe { info!(&ctx, "{}", (*payload).data) };

    Ok(xdp_action::XDP_PASS)

    // return Ok(if matched {
    //     xdp_action::XDP_PASS
    // } else {
    //     xdp_action::XDP_DROP
    // });
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
