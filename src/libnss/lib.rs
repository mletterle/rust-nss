#[link(name = "nss", vers = "0.0")]

use std::os;
use std::ptr;
use ffi::{NSS_Init, SECStatus, SECMOD_LoadUserModule, PRTrue, PRFalse, SECFailure, SECSuccess};

#[cfg(test)]
mod tests;

mod ffi;

pub fn init() -> SECStatus {
  let dir = format!("sql:{}/.pki/nssdb", os::getenv("HOME").unwrap_or(~""));
  dir.with_c_str(|nssdb| unsafe { NSS_Init(nssdb) });

  unsafe { 
      let module = *SECMOD_LoadUserModule("library=libnssckbi.so name=\"Root Certs\"".to_c_str().unwrap(),  ptr::null(), PRFalse);
      if(module.loaded != PRTrue)
      {
        return SECFailure;
      }
      
     SECSuccess
  }
}

