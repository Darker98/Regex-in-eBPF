#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use core::mem;

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

#[xdp]
pub fn xdp_redirect_payload(ctx: XdpContext) -> u32 {
    match try_xdp_redirect_payload(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED as u32,
    }
}

fn try_xdp_redirect_payload(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data;
    let data_end = ctx.data_end;

    // Parse Ethernet header
    if data + mem::size_of::<EthHdr>() > data_end {
        return Ok(xdp_action::XDP_DROP as u32);
    }

    let eth_hdr = unsafe { &*(data as *const EthHdr) };

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

    let tcp_hdr = unsafe { &*((data + tcp_offset) as *const TcpHdr) };

    // Payload starts after TCP header - send to userspace for pattern matching
    // In a real implementation, this would use AF_XDP or perf buffer
    // For now, we pass the packet through
    Ok(xdp_action::XDP_PASS as u32)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
