#![no_std]
#![no_main]

use core::mem::{self, offset_of};

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
};
use aya_log_ebpf::{info, warn};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// DHCP 协议的常量定义
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
// DHCP 选项代码
const DHCP_OPT_SERVER_ID: u8 = 54;

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
}

// DHCP 消息类型
#[repr(u8)]
enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

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

// --- Map Definitions ---

const MAX_STRING_LEN: usize = 64; // Max length for strings stored in the map

// 报文统计信息
#[map]
static mut PACKET_STATS: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

// HashMap: Key=i32, Value=Fixed-size byte array for the string
#[map]
static CONFIG_MAP: HashMap<u32, [u8; MAX_STRING_LEN]> = HashMap::with_max_entries(10, 0);

// Array Map for the shared boolean flag (using u32: 0=false, 1=true)
#[map]
static SHARED_FLAG: Array<u32> = Array::with_max_entries(1, 0);

#[classifier]
// Ingress
pub fn dhcp_replacement_ingress(mut ctx: TcContext) -> i32 {
    let ret = match try_dhcp_modifier(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    };

    ret
}

#[classifier]
// Egress
pub fn dhcp_replacement_egress(mut ctx: TcContext) -> i32 {
    let ret = match try_dhcp_modifier(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    };

    ret
}

fn try_dhcp_modifier(ctx: &mut TcContext) -> Result<i32, ()> {
    // 1. Read the shared boolean flag (key 0)
    let flag_key: u32 = 0;
    let flag_val_ptr = SHARED_FLAG.get(flag_key);
    let is_enabled = if let Some(ptr) = flag_val_ptr {
        *ptr != 0
    } else {
        warn!(ctx, "Shared flag not found in map, assuming disabled.");
        false
    };

    info!(ctx, "Shared flag enabled: {}", is_enabled as i32);

    if !is_enabled {
        return Ok(TC_ACT_PIPE);
    }

    // 获取数据包数据
    let eth_hdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };

    // 检查是否为IPv4包
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4.into() {
        return Ok(TC_ACT_PIPE); // 非IPv4包，直接放行
    }

    // 获取IPv4头
    let eth_hdr_size: usize = mem::size_of::<EthHdr>();
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, eth_hdr_size)? };

    // 检查是否为UDP包
    if unsafe { (*ipv4_hdr).proto } != IpProto::Udp.into() {
        return Ok(TC_ACT_PIPE); // 非UDP包，直接放行
    }

    let ipv4_hdr_size = unsafe { ((*ipv4_hdr).ihl() as usize) * 4 };
    let udp_hdr: *const UdpHdr = unsafe { ptr_at(ctx, eth_hdr_size + ipv4_hdr_size)? };

    // 获取UDP端口信息
    let src_port = unsafe { u16::from_be((*udp_hdr).source) };
    let dst_port = unsafe { u16::from_be((*udp_hdr).dest) };
    let udp_len = unsafe { u16::from_be((*udp_hdr).len) };

    let ipv4_src = unsafe { (*ipv4_hdr).src_addr };
    let ipv4_dst = unsafe { (*ipv4_hdr).dst_addr };
    let ipv4_proto = unsafe { (*ipv4_hdr).proto };

    let ipv4_check_offset = EthHdr::LEN + offset_of!(Ipv4Hdr, check);
    let udp_check_offset = EthHdr::LEN + ipv4_hdr_size + offset_of!(UdpHdr, check);

    // 获取用户空间配置
    let real_dhcp_server_ip = match unsafe { CONFIG_MAP.get(&ConfigKey::RealDhcpServerIp.value()) }
    {
        Some(value) => value,
        None => {
            return Ok(TC_ACT_PIPE);
        }
    };
    let real_dhcp_server_ip = unsafe { *(real_dhcp_server_ip.as_ptr() as *const u32) };
    let real_dhcp_server_mac =
        match unsafe { CONFIG_MAP.get(&ConfigKey::RealDhcpServerMac.value()) } {
            Some(value) => value,
            None => {
                return Ok(TC_ACT_PIPE);
            }
        };

    let spoofed_dhcp_server_ip =
        match unsafe { CONFIG_MAP.get(&ConfigKey::SpoofedDhcpServerIp.value()) } {
            Some(value) => value,
            None => {
                return Ok(TC_ACT_PIPE);
            }
        };
    let spoofed_dhcp_server_ip = unsafe { *(spoofed_dhcp_server_ip.as_ptr() as *const u32) };
    let spoofed_dhcp_server_mac =
        match unsafe { CONFIG_MAP.get(&ConfigKey::SpoofedDhcpServerMac.value()) } {
            Some(value) => value,
            None => {
                return Ok(TC_ACT_PIPE);
            }
        };

    let mut be_update_check = false;

    // 检查是否为DHCP流量
    if is_dhcp_client_to_server(src_port, dst_port, ipv4_dst, spoofed_dhcp_server_ip) {
        // 客户端发往假DHCP服务器的流量
        unsafe {
            // 更新统计信息
            if let Some(count) = PACKET_STATS.get_ptr_mut(&1) {
                *count += 1;
            } else {
                PACKET_STATS.insert(&1, &1, 0);
            }

            // 修改目标mac地址
            for i in 0..6 {
                ctx.store(i, &(real_dhcp_server_mac[i]), 0);
            }

            // 修改目标ip地址
            let ipv4_hdr_mut: *mut Ipv4Hdr = ptr_at_mut(ctx, eth_hdr_size)?;
            (*ipv4_hdr_mut).dst_addr = real_dhcp_server_ip;
        }
        be_update_check = true;
    } else if is_dhcp_server_to_client(src_port, dst_port, ipv4_src, real_dhcp_server_ip) {
        // 服务器发往客户端的流量
        unsafe {
            // 更新统计信息
            if let Some(count) = PACKET_STATS.get_ptr_mut(&2) {
                *count += 1;
            } else {
                PACKET_STATS.insert(&2, &1, 0);
            }

            // 修改源mac地址
            for i in 0..6 {
                ctx.store(6 + i, &(spoofed_dhcp_server_mac[i]), 0);
            }

            // 修改源ip地址
            let ipv4_hdr_mut: *mut Ipv4Hdr = ptr_at_mut(ctx, eth_hdr_size)?;
            (*ipv4_hdr_mut).src_addr = spoofed_dhcp_server_ip;

            // 获取DHCP消息头
            let udp_hdr_size = mem::size_of::<UdpHdr>();
            let _dhcp_hdr: *mut DhcpHeader =
                ptr_at_mut(ctx, eth_hdr_size + ipv4_hdr_size + udp_hdr_size)?;

            // 修改DHCP头中的siaddr（下一个启动服务器的IP） 一般为0不修改
            //(*dhcp_hdr).siaddr = SPOOFED_DHCP_SERVER;

            // 修改DHCP options中的server identifier
            match get_dhcp_server_id_offset(
                ctx,
                eth_hdr_size + ipv4_hdr_size + udp_hdr_size + mem::size_of::<DhcpHeader>(),
            ) {
                Ok(offset) => {
                    ctx.store(offset, &spoofed_dhcp_server_ip, 0);
                }
                Err(_) => {}
            };
        }

        be_update_check = true;
    }

    if be_update_check {
        // 对于网卡无状态卸载（Stateless Offloads）功能的数据包ip、udp校验和为0的情况，无法使用l3_csum_replace、l4_csum_replace快速更新，需要重新计算校验和

        // 重新计算IPv4校验和
        let ipv4_sum = match recalculate_ipv4_checksum(ctx, eth_hdr_size, ipv4_hdr_size) {
            Ok(sum) => sum,
            Err(_) => {
                return Ok(TC_ACT_PIPE);
            }
        };
        ctx.store(ipv4_check_offset, &ipv4_sum, 0);

        // 重新计算udp校验和
        let udp_sum = match recalculate_udp_checksum(
            ctx,
            eth_hdr_size + ipv4_hdr_size,
            udp_len,
            ipv4_src,
            ipv4_dst,
            ipv4_proto as u8,
        ) {
            Ok(sum) => sum,
            Err(_) => {
                return Ok(TC_ACT_PIPE);
            }
        };
        ctx.store(udp_check_offset, &udp_sum, 0);
    }

    Ok(TC_ACT_PIPE)
}

// 检查是否为客户端发往服务器的DHCP包
#[inline(always)]
fn is_dhcp_client_to_server(
    src_port: u16,
    dst_port: u16,
    ipv4_dst: u32,
    spoofed_dhcp_server_ip: u32,
) -> bool {
    src_port == DHCP_CLIENT_PORT
        && dst_port == DHCP_SERVER_PORT
        && ipv4_dst == spoofed_dhcp_server_ip
}

// 检查是否为服务器发往客户端的DHCP包
#[inline(always)]
fn is_dhcp_server_to_client(
    src_port: u16,
    dst_port: u16,
    ipv4_src: u32,
    real_dhcp_server_ip: u32,
) -> bool {
    src_port == DHCP_SERVER_PORT && dst_port == DHCP_CLIENT_PORT && ipv4_src == real_dhcp_server_ip
}

fn get_dhcp_server_id_offset(ctx: &TcContext, options_offset: usize) -> Result<usize, ()> {
    // DHCP魔术cookie大小为4字节
    let mut current_pos = options_offset + 4;
    let end_pos = ctx.data_end() - ctx.data();

    // 遍历所有DHCP选项
    for _ in 0..255 {
        if (current_pos + 2) >= end_pos {
            return Err(());
        }

        let option_type: u8 = match ctx.load(current_pos) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    ctx,
                    "dhcp_server_id_offset Failed to read type at offset {}: err {}",
                    current_pos,
                    e
                );
                return Err(()); // 读取失败，返回错误
            }
        };

        // 选项结束标记
        if option_type == 255 {
            break;
        }

        // 补白选项
        if option_type == 0 {
            current_pos += 1;
            continue;
        }

        let option_len: u8 = match ctx.load(current_pos + 1) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    ctx,
                    "dhcp_server_id_offset Failed to read type at offset {}: err {}",
                    current_pos,
                    e
                );
                return Err(()); // 读取失败，返回错误
            }
        };
        let len: usize = option_len.into();

        // 检查是否越界
        if (current_pos + 2 + len) > end_pos {
            break;
        }

        // 检查是否为服务器标识符选项
        if option_type == DHCP_OPT_SERVER_ID && len == 4 {
            // 返回偏移
            return Ok(current_pos + 2);
        }

        // 移动到下一个选项
        current_pos += 2 + len;
    }

    Err(())
}

// 返回ipv4校验和
#[inline(always)]
fn recalculate_ipv4_checksum(
    ctx: &TcContext,
    ipv4_hdr_offset: usize,
    ipv4_hdr_size: usize,
) -> Result<u16, ()> {
    let mut sum: u32 = 0;
    let mut current_pos = ipv4_hdr_offset;
    let end_pos = current_pos + ipv4_hdr_size;
    let ipv4_check_pos = current_pos + offset_of!(Ipv4Hdr, check);

    // 手动迭代IP头中的每个16位字段，避免使用from_raw_parts
    for _ in 0..255 {
        if current_pos >= end_pos {
            break;
        }

        let word: u16 = match ctx.load(current_pos) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    ctx,
                    "ipv4_checksum Failed to read type at offset {}: err {}", current_pos, e
                );
                return Err(()); // 读取失败，返回错误
            }
        };

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
    Ok(checksum)
}

// 计算UDP校验和
#[inline(always)]
fn recalculate_udp_checksum(
    ctx: &TcContext,
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
    let udp_source: u16 = match ctx.load(udp_offset) {
        Ok(t) => t,
        Err(e) => {
            warn!(
                ctx,
                "udp_checksum Failed to read type at offset {}: err {}", udp_offset, e
            );
            return Err(()); // 读取失败，返回错误
        }
    };
    let udp_dest: u16 = match ctx.load(udp_offset + 2) {
        Ok(t) => t,
        Err(e) => {
            warn!(
                ctx,
                "udp_checksum Failed to read type at offset {}: err {}",
                udp_offset + 2,
                e
            );
            return Err(()); // 读取失败，返回错误
        }
    };
    sum += (udp_source) as u32;
    sum += (udp_dest) as u32;
    sum += u16::to_be(udp_len) as u32;

    // 计算UDP数据部分的校验和
    let udp_hdr_size = mem::size_of::<UdpHdr>();
    let data_offset = udp_offset + udp_hdr_size;

    let end_pos = ctx.data_end() - ctx.data();
    let mut current_pos = data_offset;

    // 确保我们有足够的空间来读取一个 u16
    // 之前最大值 8165
    for _ in 0..4096 {
        if current_pos + 2 > end_pos {
            break;
        }
        // 使用 load_byte 或 load_half 而不是直接访问
        // 或者确保对内存访问进行严格的边界检查
        match ctx.load::<u16>(current_pos) {
            Ok(word) => {
                // 将网络字节序转换为主机字节序，并计算校验和
                let value = word as u32;
                sum += value;
                current_pos += 2;
            }
            Err(e) => {
                warn!(
                    ctx,
                    "udp_checksum Failed to read type at offset {}: err {}", current_pos, e
                );
                return Err(());
            }
        }
    }

    // 处理可能的奇数字节
    if current_pos < end_pos {
        // 只剩下一个字节
        match ctx.load::<u8>(current_pos) {
            Ok(byte) => {
                // 主机小端直接加
                let value = byte as u32;
                sum += value;
            }
            Err(e) => {
                warn!(
                    ctx,
                    "udp_checksum Failed to read last byte at offset {}: err {}", current_pos, e
                );
                return Err(());
            }
        }
    }

    // 处理进位
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // 取反得到最终的校验和
    let checksum = !(sum as u16);

    // 取反得到最终校验和
    Ok(checksum)
}

// 辅助函数: 获取指定偏移量的不可变指针
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let ptr = (ctx.data() + offset) as *const T;
    if (ptr as usize) + mem::size_of::<T>() > ctx.data_end() {
        return Err(());
    }
    Ok(ptr)
}

// 辅助函数: 获取指定偏移量的可变指针
#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
