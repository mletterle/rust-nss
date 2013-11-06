#[link(name = "nss", vers = "0.0-pre")];

#[feature(struct_variant)];
#[feature(globs)];

extern mod nspr;

extern mod extra;

use std::rt::io::fs::{File, mkdir_recursive};
use std::{os, ptr, vec, str};
use std::rt::io::{Reader, Writer, io_error};
use std::rt::io::net::ip::{SocketAddr, IpAddr, Ipv4Addr};

use std::path::Path;
use std::libc::{c_void};
use std::unstable::atomics::{AtomicBool, Acquire, Release, INIT_ATOMIC_BOOL};

pub use raw::nss::*;
use nspr::raw::nspr::*;

#[cfg(test)]
mod tests;

pub mod raw { pub mod nss; }

static mut NSS_INIT_START: AtomicBool = INIT_ATOMIC_BOOL;
static mut NSS_INIT_END: AtomicBool = INIT_ATOMIC_BOOL;

static mut NSS_UNINIT_START: AtomicBool = INIT_ATOMIC_BOOL;
static mut NSS_UNINIT_END: AtomicBool = INIT_ATOMIC_BOOL;



pub struct NSS { 

    priv nss_ctx: Option<*c_void>,
    priv nss_cert_mod: Option<SECMODModule>,
    cfg_dir: Option<~str>,
}

impl NSS {

pub fn new() -> NSS {
 NSS { nss_ctx: None, nss_cert_mod: None, cfg_dir: None,  }
}

pub fn set_cfg_dir(&mut self, cfg_dir: &str)
{
  self.cfg_dir = Some(cfg_dir.to_owned());
}

pub fn init(&mut self) -> SECStatus {
unsafe {
  if(NSS_IsInitialized() == PRTrue ) { return SECSuccess; }
  if NSS_INIT_START.swap(true, Acquire) { while !NSS_INIT_END.load(Release) { std::task::deschedule(); } }

  self.cfg_dir = match self.cfg_dir { 
            None => Some(os::getenv("SSL_DIR").unwrap_or(format!("{}/.pki/nssdb", os::getenv("HOME").unwrap_or(~".")).to_owned())),
            Some(ref s) => Some(s.to_owned()), };
  let cfg_dir = match self.cfg_dir { 
            Some(ref s) => s.to_owned(),
            None => ~"", };
  let mut cfg_path = Path::new(cfg_dir.clone());                              
  let mut nss_path = format!("sql:{}", cfg_dir);

  if(!cfg_path.exists()) {
          let system_path = &Path::new("/etc/pki/nssdb");
          if(!system_path.exists()) {
             do io_error::cond.trap(|_|{}).inside { mkdir_recursive(&cfg_path, 0b111_111_111); }
          }
          else {
            cfg_path = Path::new("/etc/pki/nssdb");
            nss_path = format!("sql:{}", system_path.as_str().unwrap());
          }
     }

     if(cfg_path.exists()) {
        nss_path.with_c_str(|nssdb| self.nss_ctx = Some(NSS_InitContext(nssdb, ptr::null(), ptr::null(), ptr::null(), ptr::null(), NSS_INIT_PK11RELOAD)));
     }

     if(NSS_IsInitialized() == PRFalse) {
                if(NSS_NoDB_Init(ptr::null()) == SECFailure){
                    fail!("NSS is borked!");
                }
     }
 
  do nss_cmd { NSS_SetDomesticPolicy() };
  self.nss_cert_mod = Some(*SECMOD_LoadUserModule("library=libnssckbi.so name=\"Root Certs\"".to_c_str().unwrap(),  ptr::null(), PRFalse));
  if(self.nss_cert_mod.unwrap().loaded != PRTrue) {
     return SECFailure;
  }
  NSS_INIT_END.store(true, Release);
 
  if(NSS_IsInitialized() == PRTrue) {
    SECSuccess
  }
  else {
    SECFailure
  } 

 }
}

pub fn uninit(&mut self) -> SECStatus {
    unsafe {
    if(NSS_IsInitialized() == PRFalse) { return SECSuccess; }
    if NSS_UNINIT_START.swap(true, Acquire) { while !NSS_UNINIT_END.load(Release) { std::task::deschedule(); } }
    SECMOD_DestroyModule(&self.nss_cert_mod.unwrap());
    if(!self.nss_ctx.is_none()) { NSS_ShutdownContext(self.nss_ctx.unwrap()) };
    self.nss_ctx = None;
    NSS_UNINIT_END.store(true, Release);
    }
    SECSuccess
}

pub fn trust_cert(file: ~str) -> SECStatus
{
    let path = &Path::new(file);
    let mut retStatus = SECFailure;
    if(!path.exists()){ return retStatus; }
    do io_error::cond.trap(|_| { retStatus = SECFailure; }).inside
    {
      unsafe
      {
        let pemdata = str::from_utf8_owned(File::open(path).read_to_end());
        let cert = CERT_DecodeCertFromPackage(pemdata.to_c_str().unwrap(), pemdata.to_c_str().len() as i32);
        let trust = CERTCertTrust { sslFlags: 0, emailFlags: 0, objectSigningFlags: 0 };
        CERT_DecodeTrustString(&trust, "TCu,Cu,Tu".to_c_str().unwrap());
        retStatus = CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), cert, &trust);
      }
    }
    retStatus
}

}
pub fn nss_cmd(blk: &fn() -> SECStatus) {
    let result = blk();
    if(result == SECFailure) {
      fail!("NSS Failed with {}", get_nss_error());
    }
}

pub fn get_nss_error() -> ~str {
    unsafe { std::str::raw::from_c_str(PR_ErrorToName(PR_GetError())) }
}

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

