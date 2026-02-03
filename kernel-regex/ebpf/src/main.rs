#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use core::mem;

// Map to store pattern algorithm from userspace
#[map]
static ALGORITHM_MAP: Array<[u8; 64]> = Array::with_max_entries(256, 0);

// Map to store match results
#[map]
static RESULTS_MAP: Array<u32> = Array::with_max_entries(256, 0);

#[repr(C)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub proto: u16,
}

#[repr(C)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub identification: u16,
    pub flags_frag_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub data_offset_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

// Simple substring matching function for kernel space
#[inline]
fn match_pattern(payload: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || pattern.len() > payload.len() {
        return false;
    }

    let pattern_len = pattern.len();
    for i in 0..=(payload.len() - pattern_len) {
        let mut matched = true;
        for j in 0..pattern_len {
            if payload[i + j] != pattern[j] {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

#[xdp]
pub fn xdp_pattern_match(ctx: XdpContext) -> u32 {
    match try_xdp_pattern_match(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED as u32,
    }
}

fn try_xdp_pattern_match(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data;
    let data_end = ctx.data_end;

    // Parse Ethernet header
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_DROP as u32);
    }

    let _eth_hdr = unsafe { &*(data as *const EthHdr) };

    // Parse IP header
    let ip_offset = mem::size_of::<EthHdr>();
    if data + ip_offset + mem::size_of::<IpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS as u32);
    }

    let ip_hdr = unsafe { &*((data + ip_offset) as *const IpHdr) };

    // Check if TCP (protocol 6)
    if ip_hdr.proto != 6 {
        return Ok(xdp_action::XDP_PASS as u32);
    }

    // Parse TCP header
    let tcp_offset = ip_offset + mem::size_of::<IpHdr>();
    if data + tcp_offset + mem::size_of::<TcpHdr>() > data_end {
        return Ok(xdp_action::XDP_PASS as u32);
    }

    let _tcp_hdr = unsafe { &*((data + tcp_offset) as *const TcpHdr) };

    // Get payload
    let payload_offset = tcp_offset + mem::size_of::<TcpHdr>();
    if data + payload_offset >= data_end {
        return Ok(xdp_action::XDP_PASS as u32);
    }

    let payload_len = (data_end - (data + payload_offset)).min(256);
    let payload = unsafe {
        core::slice::from_raw_parts((data + payload_offset) as *const u8, payload_len)
    };

    // Retrieve pattern from algorithm map
    let index: u32 = 0;
    if let Some(pattern_buf) = unsafe { ALGORITHM_MAP.get(index as usize) } {
        // Find pattern length (first null byte)
        let mut pattern_len = 0;
        for (i, &byte) in pattern_buf.iter().enumerate() {
            if byte == 0 {
                pattern_len = i;
                break;
            }
        }

        if pattern_len > 0 {
            let pattern = &pattern_buf[..pattern_len];

            // Perform pattern matching
            let result = match_pattern(payload, pattern);

            // Store result in results map
            if let Some(result_entry) = unsafe { RESULTS_MAP.get_mut(0) } {
                *result_entry = if result { 1 } else { 0 };
            }

            // Return based on match
            return Ok(if result {
                xdp_action::XDP_PASS as u32
            } else {
                xdp_action::XDP_DROP as u32
            });
        }
    }

    Ok(xdp_action::XDP_PASS as u32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
