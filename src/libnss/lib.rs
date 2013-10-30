#[feature(struct_variant)];
#[feature(globs)];
#[link(name = "nss", vers = "0.0")]
extern mod nspr;

extern mod extra;

use std::os;
use std::ptr;
use std::rt::io::{Reader, Writer};
use std::rt::io::net::ip::{SocketAddr, IpAddr, Ipv4Addr};
pub use raw::nss::*;
use nspr::raw::nspr::*;
use std::libc::{c_void};
use std::vec;
use extra::sync::Mutex;

#[cfg(test)]
mod tests;

pub mod raw { pub mod nss; }

pub struct NSS { 

    nss_ctx: Option<*c_void>,
    nss_cert_mod: Option<SECMODModule>,
    nss_mutex: Mutex,
}

impl NSS {

pub fn new() -> NSS {
 NSS { nss_ctx: None, nss_cert_mod: None, nss_mutex: Mutex::new() }
}


pub fn init(&mut self) -> SECStatus {
  let no_nss = 
  do self.nss_mutex.lock {
     self.nss_ctx.is_none()
  };
  if(!no_nss) { return SECSuccess; }
  let dir = format!("sql:{}/.pki/nssdb", os::getenv("HOME").unwrap_or(~"")).to_owned();
  dir.with_c_str(|nssdb| self.nss_ctx = Some(unsafe { NSS_InitContext(nssdb, ptr::null(), ptr::null(), ptr::null(), ptr::null(), NSS_INIT_READONLY | NSS_INIT_PK11RELOAD) }));
  info!("Error {}", unsafe { std::str::raw::from_c_str(PR_ErrorToName(PR_GetError())) } );
  unsafe{  NSS_SetDomesticPolicy() };
  self.nss_cert_mod = Some(unsafe { *SECMOD_LoadUserModule("library=libnssckbi.so name=\"Root Certs\"".to_c_str().unwrap(),  ptr::null(), PRFalse)});
  if(self.nss_cert_mod.unwrap().loaded != PRTrue)
  {
     return SECFailure;
  }
  
SECSuccess
}

pub fn uninit(&mut self) -> SECStatus {
    if(self.nss_ctx.is_none()) { return SECSuccess; }
    unsafe {
    SECMOD_DestroyModule(&self.nss_cert_mod.unwrap());
    NSS_ShutdownContext(self.nss_ctx.unwrap());
    }
    self.nss_ctx = None;
    SECSuccess
}

}




pub fn ssl_connect(addr: SocketAddr, hostname: ~str) -> SSLStream
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

pub fn nss_cmd(blk: &fn() -> SECStatus) {
    let result = blk();
    if(result == SECFailure) {
      fail!("NSS Failed with {}", unsafe { std::str::raw::from_c_str(PR_ErrorToName(PR_GetError())) });
    }
}

pub struct SSLStream {
    sslfd: *c_void,
    is_eof: bool,
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

