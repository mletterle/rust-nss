#[feature(struct_variant)];
#[feature(globs)];
#[link(name = "nss", vers = "0.0")]

use std::os;
use std::ptr;
use std::rt::io::{Reader, Writer};
use std::rt::io::net::ip::{SocketAddr, IpAddr, Ipv4Addr};
use ffi::*;
use std::libc::{c_void};
use std::vec;

#[cfg(test)]
mod tests;

mod ffi;

pub struct NSS { 

    nss_ctx: Option<*c_void>,
    nss_cert_mod: Option<SECMODModule>,

}

impl NSS {

pub fn new() -> NSS {
 NSS { nss_ctx: None, nss_cert_mod: None }
}

pub fn init(&mut self) -> SECStatus {
  
  if(!self.nss_ctx.is_none()) { return SECSuccess; }
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
    let oldmodel = unsafe { PR_OpenTCPSocket(PR_AF_INET) };
    let model = unsafe { SSL_ImportFD(ptr::null(), oldmodel) };
    unsafe { SSL_OptionSet(model, SSL_ENABLE_SSL2, PRFalse) };
    unsafe { SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PRFalse) };
    unsafe { SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PRFalse) };
    let sslfd = unsafe { PR_OpenTCPSocket(PR_AF_INET) };
    unsafe { PR_Connect(sslfd, &PRNetAddr { family: PR_AF_INET, ip: PR_htonl(IpAddrToBytes(addr.ip)), port: PR_htons(addr.port), pad: [0,0,0,0,0,0,0,0] }, 30000) };
    let ssl_socket = unsafe { SSL_ImportFD(model, sslfd) };
    unsafe { PR_Close(model); }
    unsafe { SSL_ResetHandshake(ssl_socket, PRFalse); }
    unsafe { SSL_SetURL(ssl_socket, hostname.to_c_str().unwrap()); }
    unsafe { SSL_ForceHandshake(ssl_socket); }
    SSLStream { sslfd: ssl_socket, is_eof: false }   
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
     _ => Some(buf.len()) //TODO: This is certainly wrong.
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

