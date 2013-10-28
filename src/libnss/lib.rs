#[feature(struct_variant)];
#[link(name = "nss", vers = "0.0")]

use std::os;
use std::ptr;
use std::rt::io::net::ip::{SocketAddr};
use ffi::{NSS_InitContext, SECStatus, SECMOD_LoadUserModule, PRTrue, PRFalse, 
          SECFailure, SECSuccess, PR_OpenTCPSocket, PR_AF_INET, SECMOD_DestroyModule,
          NSS_ShutdownContext, SECMODModule, NSS_INIT_READONLY, NSS_INIT_PK11RELOAD};
use std::libc::{c_void};
use std::default::Default;

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
  
  info!("NSS Init - Context: {}", self.nss_ctx.is_none());
  if(self.nss_ctx.is_none()) { return SECSuccess; }
  let dir = format!("sql:{}/.pki/nssdb", os::getenv("HOME").unwrap_or(~""));
  dir.with_c_str(|nssdb| self.nss_ctx = Some(unsafe { NSS_InitContext(nssdb, ptr::null(), ptr::null(), ptr::null(), ptr::null(), NSS_INIT_READONLY | NSS_INIT_PK11RELOAD) }));

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




pub fn ssl_connect(addr: SocketAddr)
{
   let socket = unsafe { PR_OpenTCPSocket(PR_AF_INET) };
}

