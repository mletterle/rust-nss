use std::{ptr, vec};
use std::io::{Reader, Writer};
use std::io::net::ip::{SocketAddr, IpAddr, Ipv4Addr};

use std::libc::{c_void};

use nspr::raw::nspr::*;
use super::nss::*;
use super::nss::raw::*;


pub struct SSLStream {
    sslfd: *c_void,
    is_eof: bool,
}

impl SSLStream {

pub fn connect(addr: SocketAddr, hostname: ~str) -> SSLStream
{
    unsafe {

    let oldmodel = PR_OpenTCPSocket(PR_AF_INET);
    let model = SSL_ImportFD(ptr::null(), oldmodel);
    do nss_cmd { SSL_OptionSet(model, SSL_ENABLE_SSL2, PRFalse) };
    do nss_cmd { SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PRFalse) };
    do nss_cmd { SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PRFalse) };
    let sslfd = PR_OpenTCPSocket(PR_AF_INET);
    PR_Connect(sslfd, &PRNetAddr { family: PR_AF_INET, ip: PR_htonl(IpAddrToBytes(addr.ip)), port: PR_htons(addr.port), pad: [0,0,0,0,0,0,0,0] }, 30000);
    let ssl_socket = SSL_ImportFD(model, sslfd);
    PR_Close(model); 
    do nss_cmd { SSL_ResetHandshake(ssl_socket, PRFalse) };
    do nss_cmd { SSL_SetURL(ssl_socket, hostname.to_c_str().unwrap()) };
    do nss_cmd { SSL_ForceHandshake(ssl_socket) };
    
    SSLStream { sslfd: ssl_socket, is_eof: false }   

    }
}


pub fn disconnect(&mut self) -> PRStatus {
        unsafe { PR_Close(self.sslfd) }
}

}

impl Reader for SSLStream {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
    match unsafe { PR_Read(self.sslfd, vec::raw::to_ptr(buf) as *c_void, buf.len() as i32) } {
     0 => { self.is_eof = true; None },
     -1 => None,
     bytes_read => Some(bytes_read as uint)
    }
}
       fn eof(&mut self) -> bool {
            self.is_eof
       }
}

impl Writer for SSLStream {
    fn write(&mut self, buf: &[u8]) {
        unsafe { PR_Write(self.sslfd, vec::raw::to_ptr(buf) as *c_void, buf.len() as i32) };
    }
    fn flush(&mut self) {
        //nop
    }
}

pub fn IpAddrToBytes(addr: IpAddr) -> u32 {
match addr {
        Ipv4Addr(o1, o2, o3, o4) => ((o1 as u32 << 24) + (o2 as u32 << 16) + (o3 as u32 << 8) + (o4 as u32 << 0)) as u32,
        _ => 0u32 }
}
