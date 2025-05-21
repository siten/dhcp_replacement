use aya::programs::{tc, SchedClassifier, TcAttachType};
use clap::Parser;
#[rustfmt::skip]
use log::{info, debug, warn};
use tokio::signal;

use anyhow::{anyhow, Context, Error, Ok};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap},
    Bpf,
};
use aya_log::BpfLogger;
use std::{convert::TryInto, fmt, net::Ipv4Addr, str};

use core::mem::{self, offset_of};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::{
    packet::arp::{ArpOperations, ArpPacket, MutableArpPacket},
    util::Octets,
};
use pnet_datalink::{self, Channel, MacAddr};
use std::process; // To exit gracefully
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

const MAX_STRING_LEN: usize = 64;

// 定义键枚举
#[derive(Debug, Clone, Copy)]
enum ConfigKey {
    RealDhcpServerIp = 1,
    RealDhcpServerMac = 2,
    SpoofedDhcpServerIp = 3,
    SpoofedDhcpServerMac = 4,
}

impl ConfigKey {
    fn value(&self) -> u32 {
        *self as u32
    }

    fn as_str(&self) -> &'static str {
        match self {
            ConfigKey::RealDhcpServerIp => "REAL_DHCP_SERVER_IP",
            ConfigKey::RealDhcpServerMac => "REAL_DHCP_SERVER_MAC",
            ConfigKey::SpoofedDhcpServerIp => "SPOOFED_DHCP_SERVER_IP",
            ConfigKey::SpoofedDhcpServerMac => "SPOOFED_DHCP_SERVER_MAC",
        }
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// 配置值特征
trait ConfigValue {
    fn as_bytes(&self) -> Vec<u8>;
    fn to_display_string(&self) -> String;
}

// IPv4 地址实现
impl ConfigValue for Ipv4Addr {
    fn as_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }

    fn to_display_string(&self) -> String {
        self.to_string()
    }
}

impl ConfigValue for MacAddr {
    fn as_bytes(&self) -> Vec<u8> {
        self.octets().to_vec()
    }

    fn to_display_string(&self) -> String {
        self.octets()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":")
    }
}

#[cfg(feature = "test-check-sum")]
// DHCP 消息头结构体
#[repr(C, packed)]
struct DhcpHeader {
    op: u8,           // 消息类型，1=请求，2=响应
    htype: u8,        // 硬件地址类型
    hlen: u8,         // 硬件地址长度
    hops: u8,         // DHCP中继代理使用
    xid: u32,         // 事务ID
    secs: u16,        // 客户端启动后的秒数
    flags: u16,       // 标志位
    ciaddr: u32,      // 客户端IP地址
    yiaddr: u32,      // 分配给客户端的IP
    siaddr: u32,      // 下一个启动服务器的IP
    giaddr: u32,      // 中继代理IP地址
    chaddr: [u8; 16], // 客户端硬件地址
    sname: [u8; 64],  // 服务器主机名
    file: [u8; 128],  // 启动文件名
                      // 魔术cookie和选项字段在此之后
}

// 定义 PacketData 结构体
#[cfg(feature = "test-check-sum")]
pub struct PacketData {
    data: [u8; 338],
}

#[cfg(feature = "test-check-sum")]
impl PacketData {
    pub fn new() -> Self {
        // dhcp offer server_id_offset 299
        let data1 = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe8, 0x9c, 0x25, 0x2b, 0x9b, 0x7b, 0x8, 0x0, 0x45,
            0x0, 0x1, 0x28, 0xe2, 0xd2, 0x0, 0x0, 0x80, 0x11, 0x0, 0x0, 0xc0, 0xa8, 0x32, 0x63,
            0xff, 0xff, 0xff, 0xff, 0x0, 0x43, 0x0, 0x44, 0x1, 0x14, 0xf4, 0x30, 0x2, 0x1, 0x6,
            0x0, 0xaa, 0x2b, 0x66, 0x2c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x32,
            0xb0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x98, 0xc3, 0x79, 0x95, 0x54, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x44, 0x45, 0x53, 0x4b, 0x54, 0x4f, 0x50,
            0x2d, 0x48, 0x4d, 0x4a, 0x55, 0x39, 0x31, 0x43, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x63,
            0x82, 0x53, 0x63, 0x35, 0x1, 0x2, 0x33, 0x4, 0x0, 0x0, 0x1, 0x68, 0x3, 0x4, 0xc0, 0xa8,
            0x32, 0x63, 0x36, 0x4, 0xc0, 0xa8, 0x32, 0x63, 0x1, 0x4, 0xff, 0xff, 0xff, 0x0, 0xff,
        ];

        // dhcp request ipv4_sum 0x371d udp_sum 0xe2a9 server_id_offset 0
        let data2 = [
            0xe8, 0x9c, 0x25, 0x2b, 0x9b, 0x7b, 0x10, 0x98, 0xc3, 0x79, 0x95, 0x54, 0x8, 0x0, 0x45,
            0x0, 0x1, 0x44, 0x1c, 0x28, 0x40, 0x0, 0x40, 0x11, 0x37, 0x1d, 0xc0, 0xa8, 0x32, 0xb0,
            0xc0, 0xa8, 0x32, 0x63, 0x0, 0x44, 0x0, 0x43, 0x1, 0x30, 0xe2, 0xa9, 0x1, 0x1, 0x6,
            0x0, 0x81, 0xee, 0x4b, 0x42, 0x0, 0x0, 0x0, 0x0, 0xc0, 0xa8, 0x32, 0xb0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x98, 0xc3, 0x79, 0x95, 0x54, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x63, 0x82, 0x53,
            0x63, 0x35, 0x1, 0x3, 0x3d, 0x7, 0x1, 0x10, 0x98, 0xc3, 0x79, 0x95, 0x54, 0x39, 0x2,
            0x5, 0xdc, 0x3c, 0xe, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x2d, 0x64, 0x68, 0x63,
            0x70, 0x2d, 0x39, 0xc, 0x8, 0x73, 0x61, 0x6e, 0x2d, 0x78, 0x69, 0x6e, 0x67, 0x37, 0xa,
            0x1, 0x3, 0x6, 0xf, 0x1a, 0x1c, 0x33, 0x3a, 0x3b, 0x2b, 0xff, 0x0,
        ];

        Self { data: data2 }
        //PacketData { data :data1 }
    }

    // 返回数组开始地址作为 usize
    pub fn data(&self) -> usize {
        self.data.as_ptr() as usize
    }

    // 返回数组结束地址作为 usize（指向最后一个元素之后的位置）
    pub fn data_end(&self) -> usize {
        (self.data.as_ptr() as usize) + self.data.len()
    }

    // 获取数据的引用
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    // 获取数据的可变引用
    pub fn get_data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

// 返回ipv4校验和计算函数
#[cfg(feature = "test-check-sum")]
#[inline(always)]
fn recalculate_ipv4_checksum(
    ctx: &PacketData,
    ipv4_hdr_offset: usize,
    ipv4_hdr_size: usize,
) -> Result<u16, ()> {
    let mut sum: u32 = 0;
    let mut current_pos = ipv4_hdr_offset;
    let end_pos = current_pos + ipv4_hdr_size;
    let ipv4_check_pos = current_pos + offset_of!(Ipv4Hdr, check);

    // 手动迭代IP头中的每个16位字段
    for _ in 0..255 {
        if current_pos >= end_pos {
            break;
        }
        let word_ptr = (ctx.data() + current_pos) as *const u16;
        let word = unsafe { *word_ptr };
        let value = word as u32;

        // 累加16位值
        if current_pos != ipv4_check_pos {
            sum += value;
        } else {
            // 原校验和位置
            sum += 0;
        }

        current_pos += 2;
    }

    // 处理进位
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // 取反
    let checksum = !(sum as u16);
    Ok(checksum).map_err(|_| ())
}

// 计算UDP校验和
#[cfg(feature = "test-check-sum")]
#[inline(always)]
fn recalculate_udp_checksum(
    ctx: &PacketData,
    udp_offset: usize,
    udp_len: u16,
    src_ip: u32,
    dst_ip: u32,
    proto: u8,
) -> Result<u16, ()> {
    // 创建UDP伪头部用于校验和计算
    let mut sum: u32 = 0;

    // 源IP和目标IP (IPv4伪头部的一部分)
    sum += (((src_ip >> 16) & 0xFFFF) as u16) as u32;
    sum += ((src_ip & 0xFFFF) as u16) as u32;
    sum += (((dst_ip >> 16) & 0xFFFF) as u16) as u32;
    sum += ((dst_ip & 0xFFFF) as u16) as u32;

    // 添加协议字段
    sum += u16::to_be(proto as u16) as u32;

    // 添加UDP长度
    sum += u16::to_be(udp_len) as u32;

    // 添加UDP头部字段
    let word_ptr = (ctx.data() + udp_offset) as *const u16;
    let udp_source = unsafe { *word_ptr };
    let word_ptr = (ctx.data() + udp_offset + 2) as *const u16;
    let udp_dest = unsafe { *word_ptr };

    sum += (udp_source) as u32;
    sum += (udp_dest) as u32;
    sum += u16::to_be(udp_len) as u32;

    // 计算UDP数据部分的校验和
    let udp_hdr_size = mem::size_of::<UdpHdr>();
    let data_offset = udp_offset + udp_hdr_size;

    let end_pos = ctx.data_end() - ctx.data();
    let mut current_pos = data_offset;

    // 确保我们有足够的空间来读取一个 u16
    for _ in 0..4096 {
        if current_pos + 2 > end_pos {
            break;
        }
        let word_ptr = (ctx.data() + current_pos) as *const u16;
        let word = unsafe { *word_ptr };
        let value = word as u32;
        sum += value;
        current_pos += 2;
    }

    // 处理可能的奇数字节
    if current_pos < end_pos {
        // 只剩下一个字节 主机为小端
        let byte_ptr = (ctx.data() + current_pos) as *const u8;
        let byte = unsafe { *byte_ptr };
        let value = byte as u32;
        sum += value;
    }

    // 处理进位
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 取反得到最终的校验和
    let checksum = !(sum as u16);

    // 取反得到最终校验和
    Ok(checksum).map_err(|_| ())
}

// 获取DHCP Server Identifier偏移
#[cfg(feature = "test-check-sum")]
fn get_dhcp_server_id_offset(ctx: &PacketData, options_offset: usize) -> Result<usize, ()> {
    // DHCP魔术cookie大小为4字节
    let mut current_pos = options_offset + 4;
    let end_pos = ctx.data_end() - ctx.data();

    // 遍历所有DHCP选项
    for _ in 0..255 {
        if (current_pos + 2) >= end_pos {
            return Err(());
        }

        // let option_type: u8 = match ctx.load(current_pos) {
        //     Ok(t) => t,
        //     Err(e) => {
        //         info!(
        //             ctx,
        //             "Failed to read type at offset {}: err {}", current_pos, e
        //         );
        //         return Err(()); // 读取失败，返回错误
        //     }
        // };
        let byte_ptr = (ctx.data() + current_pos) as *const u8;
        let option_type = unsafe { *byte_ptr };

        // 选项结束标记
        if option_type == 255 {
            break;
        }

        // 补白选项
        if option_type == 0 {
            current_pos += 1;
            continue;
        }

        // let option_len: u8 = match ctx.load(current_pos + 1) {
        //     Ok(t) => t,
        //     Err(e) => {
        //         info!(
        //             ctx,
        //             "Failed to read type at offset {}: err {}", current_pos, e
        //         );
        //         return Err(()); // 读取失败，返回错误
        //     }
        // };
        let byte_ptr = (ctx.data() + current_pos + 1) as *const u8;
        let option_len = unsafe { *byte_ptr };
        let len: usize = option_len.into();

        // 检查是否越界
        if (current_pos + 2 + len) > end_pos {
            break;
        }

        // 检查是否为服务器标识符选项
        if option_type == 54 && len == 4 {
            // 返回偏移
            return Ok(current_pos + 2).map_err(|_| ());
        }

        // 移动到下一个选项
        current_pos += 2 + len;
    }

    Err(())
}

// 辅助函数: 获取指定偏移量的不可变指针
#[cfg(feature = "test-check-sum")]
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &PacketData, offset: usize) -> Result<*const T, ()> {
    let ptr = (ctx.data() + offset) as *const T;
    if (ptr as usize) + mem::size_of::<T>() > ctx.data_end() {
        return Err(());
    }
    Ok(ptr).map_err(|_| ())
}

// 辅助函数: 获取指定偏移量的可变指针
#[cfg(feature = "test-check-sum")]
#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &PacketData, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T).map_err(|_| ())
}

// 添加测试相关的主函数部分
#[cfg(feature = "test-check-sum")]
async fn run_test_checksum() -> anyhow::Result<()> {
    let packet = PacketData::new();

    // 获取数据包数据
    let eth_hdr: *const EthHdr = match unsafe { ptr_at(&packet, 0) } {
        anyhow::Result::Ok(ret) => ret,
        anyhow::Result::Err(_) => {
            return Err(anyhow!("Failed to get pointer to eth_hdr"));
        }
    };

    // 检查是否为IPv4包
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4.into() {
        return Err(anyhow!("Not an IPv4 packet"));
    }

    // 获取IPv4头
    let eth_hdr_size: usize = mem::size_of::<EthHdr>();
    let ipv4_hdr: *const Ipv4Hdr = match unsafe { ptr_at(&packet, eth_hdr_size) } {
        anyhow::Result::Ok(ret) => ret,
        anyhow::Result::Err(_) => {
            return Err(anyhow!("Failed to get pointer to ipv4_hdr"));
        }
    };

    // 检查是否为UDP包
    if unsafe { (*ipv4_hdr).proto } != IpProto::Udp.into() {
        return Err(anyhow!("Not a UDP packet"));
    }

    let ipv4_hdr_size = unsafe { ((*ipv4_hdr).ihl() as usize) * 4 };
    let udp_hdr: *const UdpHdr = match unsafe { ptr_at(&packet, eth_hdr_size + ipv4_hdr_size) } {
        anyhow::Result::Ok(ret) => ret,
        anyhow::Result::Err(_) => {
            return Err(anyhow!("Failed to get pointer to udp_hdr"));
        }
    };

    // 获取UDP端口信息
    let src_port = unsafe { u16::from_be((*udp_hdr).source) };
    let dst_port = unsafe { u16::from_be((*udp_hdr).dest) };
    let udp_len = unsafe { u16::from_be((*udp_hdr).len) };

    let ipv4_src = unsafe { (*ipv4_hdr).src_addr };
    let ipv4_dst = unsafe { (*ipv4_hdr).dst_addr };
    let ipv4_proto = unsafe { (*ipv4_hdr).proto };

    let ipv4_check_offset = EthHdr::LEN + offset_of!(Ipv4Hdr, check);
    let udp_check_offset = EthHdr::LEN + ipv4_hdr_size + offset_of!(UdpHdr, check);

    // 计算校验和
    let ipv4_sum = match recalculate_ipv4_checksum(&packet, eth_hdr_size, ipv4_hdr_size) {
        anyhow::Result::Ok(ret) => ret,
        _ => 0,
    };
    let udp_sum = match recalculate_udp_checksum(
        &packet,
        eth_hdr_size + ipv4_hdr_size,
        udp_len,
        ipv4_src,
        ipv4_dst,
        ipv4_proto as u8,
    ) {
        anyhow::Result::Ok(ret) => ret,
        _ => 0,
    };

    let udp_hdr_size = mem::size_of::<UdpHdr>();
    let s_identifier_offset = match get_dhcp_server_id_offset(
        &packet,
        eth_hdr_size + ipv4_hdr_size + udp_hdr_size + mem::size_of::<DhcpHeader>(),
    ) {
        anyhow::Result::Ok(ret) => ret,
        anyhow::Result::Err(_) => 0 as usize,
    };

    println!(
        "ipv4_sum : {} udp_sum : {} server_id_offset : {}",
        ipv4_sum, udp_sum, s_identifier_offset
    );

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    get_endian_info();
    // 测试模式的代码
    #[cfg(feature = "test-check-sum")]
    {
        println!("运行测试校验和模式...");
        //run_test_checksum().await;
        return run_test_checksum().await;
    }

    // 正常模式的代码
    #[cfg(not(feature = "test-check-sum"))]
    {
        let opt = Opt::parse();
        let Opt { iface } = opt;
        let target_ip = "192.168.20.2";

        let (real_dhcp_server_ip, real_dhcp_server_mac) = match get_interface_info_by_name(&iface) {
            anyhow::Result::Ok((ipv4_addr, mac_addr, _)) => (ipv4_addr, mac_addr),
            anyhow::Result::Err(e) => {
                return Err(e);
            }
        };

        let (spoofed_dhcp_server_ip, spoofed_dhcp_server_mac) =
            match get_mac_by_ip(&iface, target_ip) {
                anyhow::Result::Ok((ipv4_addr, mac_addr)) => (ipv4_addr, mac_addr),
                anyhow::Result::Err(e) => {
                    return Err(e);
                }
            };

        env_logger::init();

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        // 加载 eBPF 程序
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/dhcp_replacement"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        // --- 与 Map 交互 ---

        // 1. 获取 CONFIG_MAP (HashMap) 的句柄
        let mut config_map: HashMap<_, u32, [u8; MAX_STRING_LEN]> = ebpf
            .map_mut("CONFIG_MAP")
            .context("Failed to find CONFIG_MAP")?
            .try_into()?;

        info!("Populating HashMap...");
        // 将配置值和键组织在一起
        let entries: Vec<(ConfigKey, Box<dyn ConfigValue>)> = vec![
            (ConfigKey::RealDhcpServerIp, Box::new(real_dhcp_server_ip)),
            (ConfigKey::RealDhcpServerMac, Box::new(real_dhcp_server_mac)),
            (
                ConfigKey::SpoofedDhcpServerIp,
                Box::new(spoofed_dhcp_server_ip),
            ),
            (
                ConfigKey::SpoofedDhcpServerMac,
                Box::new(spoofed_dhcp_server_mac),
            ),
        ];

        // 2. 向 CONFIG_MAP (HashMap) 中填充数据
        for (key, value) in entries {
            let bytes = value.as_bytes();
            let mut config_value = [0u8; MAX_STRING_LEN];
            config_value[..bytes.len()].copy_from_slice(&bytes);

            let hex_value: String = bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<String>>()
                .join(" ");

            info!(
                "  Adding key={} ({}), value='{}' ({})",
                key.value(),
                key,
                hex_value,
                value.to_display_string()
            );

            config_map
                .insert(&key.value(), &config_value, 0)
                .with_context(|| {
                    format!("Failed to insert key {} ({}) into map", key.value(), key)
                })?;
        }
        info!("HashMap populated.");

        // 3. 获取 SHARED_FLAG map 的句柄
        let mut shared_flag: Array<_, u32> = ebpf
            .map_mut("SHARED_FLAG")
            .context("Failed to find SHARED_FLAG map")?
            .try_into()?;

        // 4. 设置 SHARED_FLAG 初始标志值
        let flag_key: u32 = 0;
        let enable_flag_val: u32 = 1; // 1 表示 true
        info!("Setting shared flag to 'true' (1)");
        shared_flag
            .set(flag_key, &enable_flag_val, 0)
            .context("Failed to set shared flag")?;

        // 错误添加 clsact 到接口如果它已经添加是无害的
        // 完全清理可以用 'sudo tc qdisc del dev eth0 clsact' 完成
        let _ = tc::qdisc_add_clsact(&iface);
        let program_ingress: &mut SchedClassifier = ebpf
            .program_mut("dhcp_replacement_ingress")
            .unwrap()
            .try_into()?;
        program_ingress.load()?;
        program_ingress.attach(&iface, TcAttachType::Ingress)?;

        let program_egress: &mut SchedClassifier = ebpf
            .program_mut("dhcp_replacement_egress")
            .unwrap()
            .try_into()?;
        program_egress.load()?;
        program_egress.attach(&iface, TcAttachType::Egress)?;

        let ctrl_c = signal::ctrl_c();
        println!("Waiting for Ctrl-C...");
        ctrl_c.await?;
        println!("Exiting...");
    }

    Ok(())
}

pub fn get_interface_info_by_name(
    interface_name: &str,
) -> anyhow::Result<(Ipv4Addr, MacAddr, pnet_datalink::NetworkInterface)> {
    // 获取所有网络接口
    let interfaces = pnet_datalink::interfaces();

    // 收集所有接口信息用于可能的错误消息
    let mut all_interfaces_info = Vec::new();

    // 遍历所有接口并收集信息
    for iface in &interfaces {
        let ip_str = iface
            .ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.ip().to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let mac_str = iface
            .mac
            .map(|mac| mac.to_string())
            .unwrap_or_else(|| "No MAC".to_string());

        all_interfaces_info.push(format!(
            "Interface: {}, IP: [{}], MAC: {}",
            iface.name, ip_str, mac_str
        ));
    }

    // 查找指定名称的网络接口
    let interface = match interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
    {
        Some(iface) => iface,
        None => {
            // 打印所有接口信息并返回错误
            println!("Available interfaces:");
            for info in all_interfaces_info {
                println!("{}", info);
            }
            return Err(anyhow!("Network interface not found: {}", interface_name));
        }
    };

    // 获取接口的 IPv4 地址
    let ipv4_addr = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        },
        None => {
            // 打印所有接口信息并返回错误
            println!("Available interfaces:");
            for info in all_interfaces_info {
                println!("{}", info);
            }
            return Err(anyhow!(
                "Network interface {} not found IPv4 address",
                interface_name
            ));
        }
    };

    // 获取接口的 MAC 地址
    let mac_addr = match interface.mac {
        Some(mac) => mac,
        None => {
            // 打印所有接口信息并返回错误
            println!("Available interfaces:");
            for info in all_interfaces_info {
                println!("{}", info);
            }
            return Err(anyhow!(
                "Network interface {} not found MAC address",
                interface_name
            ));
        }
    };

    Ok((ipv4_addr, mac_addr, interface))
}

fn get_local_adapters_info() {
    println!("Fetching network interfaces...");

    // Get all network interfaces using pnet_datalink
    let interfaces = pnet_datalink::interfaces();

    if interfaces.is_empty() {
        println!("No network interfaces found.");
        return;
    }

    println!("Found {} network interfaces:", interfaces.len());
    println!("-------------------------------------");

    // Iterate over each interface
    for itf in interfaces.iter() {
        println!("Interface: {}", itf.name);

        // Print MAC Address if available
        match itf.mac {
            Some(mac) => println!("  MAC Address: {}", mac),
            None => println!("  MAC Address: N/A"),
        }

        // Print IP Addresses (IPv4 and IPv6)
        if itf.ips.is_empty() {
            println!("  No IP Addresses assigned.");
        } else {
            println!("  IP Addresses:");
            for ip_network in itf.ips.iter() {
                match ip_network {
                    pnet::ipnetwork::IpNetwork::V4(v4_net) => {
                        // Extract the IPv4 address
                        let ip = v4_net.ip();

                        // Calculate netmask from prefix length
                        let netmask = v4_net.mask();

                        // Calculate broadcast address
                        let broadcast = v4_net.broadcast();

                        println!(
                            "    - IPv4: {} (Netmask: {}, Broadcast: {})",
                            ip, netmask, broadcast
                        );
                    }
                    pnet::ipnetwork::IpNetwork::V6(v6_net) => {
                        // Extract the IPv6 address
                        let ip = v6_net.ip();

                        // Calculate netmask from prefix length
                        let netmask = v6_net.mask();

                        // IPv6 doesn't always have a broadcast address in the same sense as IPv4
                        let broadcast = "N/A".to_string();

                        println!(
                            "    - IPv6: {} (Netmask: {}, Broadcast: {})",
                            ip, netmask, broadcast
                        );
                    }
                }
            }
        }
        println!("-------------------------------------");
    }
}

const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28; // Standard ARP packet size for IPv4 over Ethernet

fn get_mac_by_ip(interface_name: &str, target_ip_str: &str) -> anyhow::Result<(Ipv4Addr, MacAddr)> {
    let target_ip = match Ipv4Addr::from_str(target_ip_str) {
        anyhow::Result::Ok(ip) => ip,
        anyhow::Result::Err(e) => {
            eprintln!(
                "Error: Invalid IPv4 address format provided: {}",
                target_ip_str
            );
            return Err(anyhow!(e));
        }
    };

    let (source_ip, source_mac, interface) = match get_interface_info_by_name(interface_name) {
        anyhow::Result::Ok((ipv4_addr, mac_addr, interface)) => (ipv4_addr, mac_addr, interface),
        anyhow::Result::Err(e) => {
            return Err(anyhow!(e));
        }
    };

    println!(
        "Using interface: {} (IP: {}, MAC: {})",
        interface_name, source_ip, source_mac
    );
    println!("Sending ARP request for IP: {}", target_ip);

    // --- Create Datalink Channel ---
    // We need a channel to send/receive raw Ethernet frames.
    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        anyhow::Result::Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        anyhow::Result::Ok(_) => {
            return Err(anyhow!(
                "Unsupported channel type for interface '{}'.",
                interface.name
            ));
        }
        anyhow::Result::Err(e) => {
            eprintln!("Hint: Try running with root/administrator privileges.");
            return Err(anyhow!(
                "Error creating datalink channel for interface '{}': {}",
                interface.name,
                e
            ));
        }
    };

    // --- Build ARP Request Packet ---
    let mut ethernet_buffer = [0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or_else(|| anyhow!("Create MutableEthernetPacket fail."))?;

    ethernet_packet.set_destination(MacAddr::broadcast()); // Destination MAC: FF:FF:FF:FF:FF:FF
    ethernet_packet.set_source(source_mac); // Source MAC: Our interface's MAC
    ethernet_packet.set_ethertype(EtherTypes::Arp); // EtherType: 0x0806 (ARP)

    let mut arp_buffer = [0u8; ARP_PACKET_LEN];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
        .ok_or_else(|| anyhow!("Create MutableArpPacket fail."))?;

    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet); // Hardware Type: Ethernet (1)
    arp_packet.set_protocol_type(EtherTypes::Ipv4); // Protocol Type: IPv4 (0x0800)
    arp_packet.set_hw_addr_len(6); // Hardware Address Length: 6 (for MAC)
    arp_packet.set_proto_addr_len(4); // Protocol Address Length: 4 (for IPv4)
    arp_packet.set_operation(ArpOperations::Request); // Operation Code: Request (1)
    arp_packet.set_sender_hw_addr(source_mac); // Sender MAC: Our MAC
    arp_packet.set_sender_proto_addr(source_ip); // Sender IP: Our IP
    arp_packet.set_target_hw_addr(MacAddr::zero()); // Target MAC: 00:00:00:00:00:00 (unknown)
    arp_packet.set_target_proto_addr(target_ip); // Target IP: The IP we are querying

    // Set the ARP packet as the payload of the Ethernet frame
    ethernet_packet.set_payload(arp_packet.packet());

    // --- Send ARP Request ---
    match tx.send_to(ethernet_packet.packet(), None) {
        Some(anyhow::Result::Ok(())) => {
            println!("ARP Request sent successfully.");
        }
        Some(Err(e)) => {
            return Err(anyhow!("Error sending ARP request: {}", e));
        }
        None => {
            return Err(anyhow!("send_to returned None (interface may be down?)."));
        }
    }

    // --- Receive and Process ARP Reply ---
    println!("Waiting for ARP Reply...");
    let start_time = Instant::now();
    let timeout = Duration::from_secs(3); // Wait for 3 seconds

    loop {
        // Check for timeout
        if start_time.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for ARP reply from {}", target_ip));
        }

        match rx.next() {
            anyhow::Result::Ok(packet) => {
                let received_ethernet_packet = EthernetPacket::new(packet)
                    .ok_or_else(|| anyhow!("Create EthernetPacket fail."))?;

                // Check if it's an ARP packet targeted at us
                if received_ethernet_packet.get_ethertype() == EtherTypes::Arp
                    && received_ethernet_packet.get_destination() == source_mac
                {
                    if let Some(received_arp_packet) =
                        ArpPacket::new(received_ethernet_packet.payload())
                    {
                        // Check if it's an ARP Reply and if it's from the target IP
                        if received_arp_packet.get_operation() == ArpOperations::Reply
                            && received_arp_packet.get_sender_proto_addr() == target_ip
                            && received_arp_packet.get_target_proto_addr() == source_ip
                        {
                            // Ensure it's a reply to us
                            let target_mac = received_arp_packet.get_sender_hw_addr();
                            println!("MAC Address Found: {} -> {}", target_ip, target_mac);
                            // Success!
                            return anyhow::Result::Ok((target_ip, target_mac));
                        }
                    }
                }
            }
            anyhow::Result::Err(e) => {
                // Handle errors like "timed out" if channel isn't configured for blocking
                // Or other potential I/O errors
                eprintln!("Error receiving packet: {}", e);
                // Maybe add a small delay before retrying to avoid busy-waiting on transient errors
                thread::sleep(Duration::from_millis(50));
                // Consider if the error is fatal and should exit
            }
        }
    }
}

// 查看目标平台大小端
fn get_endian_info() {
    let x: u32 = 0x01020304;
    let first_byte = (x & 0xff) as u8;

    if first_byte == 0x04 {
        println!("小端字节序 (Little Endian)");
    } else if first_byte == 0x01 {
        println!("大端字节序 (Big Endian)");
    } else {
        println!("混合字节序");
    }
}
