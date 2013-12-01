extern mod std;

use std::io::fs::{File, mkdir_recursive};
use std::{os, ptr, str};
use std::io::{Reader, io_error};

use std::path::Path;
use std::libc::{c_void};
use std::unstable::atomics::{AtomicBool, Acquire, Release, INIT_ATOMIC_BOOL};

use nspr::raw::nspr::*;
use super::nss::raw::*;

static mut NSS_INIT_START: AtomicBool = INIT_ATOMIC_BOOL;
static mut NSS_INIT_END: AtomicBool = INIT_ATOMIC_BOOL;

static mut NSS_UNINIT_START: AtomicBool = INIT_ATOMIC_BOOL;
static mut NSS_UNINIT_END: AtomicBool = INIT_ATOMIC_BOOL;

pub mod raw;


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

pub fn nodb_init(&mut self) -> SECStatus {
unsafe {
        if(self.start_init() == SECSuccess) { return SECSuccess; }

        if(NSS_NoDB_Init(ptr::null()) == SECFailure){
             fail!("NSS is borked!");
        }

        self.finish_init()
}
}

fn start_init(&mut self) -> SECStatus {
unsafe {
  if(NSS_IsInitialized() == PRTrue ) { return SECSuccess; }
  if NSS_INIT_START.swap(true, Acquire) { while !NSS_INIT_END.load(Release) { std::task::deschedule(); } }
  SECFailure //Not really...
}
}

pub fn init(&mut self) -> SECStatus {
unsafe {
  if(self.start_init() == SECSuccess) { return SECSuccess; }
  self.cfg_dir = match self.cfg_dir { 
            None => Some(os::getenv("SSL_DIR").unwrap_or(format!("{}/.pki/nssdb", os::getenv("HOME").unwrap_or(~".")).to_owned())),
            Some(ref s) => Some(s.to_owned()), };
  let cfg_dir = match self.cfg_dir { 
            Some(ref s) => s.to_owned(),
            None => ~"", };
  let mut cfg_path = Path::init(cfg_dir.clone());                              
  let mut nss_path = format!("sql:{}", cfg_dir);

  if(!cfg_path.exists()) {
          let system_path = &Path::init("/etc/pki/nssdb");
          if(!system_path.exists()) {
            io_error::cond.trap(|_|{}).inside(|| mkdir_recursive(&cfg_path, 0b111_111_111));
          }
          else {
            cfg_path = Path::init("/etc/pki/nssdb");
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
  self.finish_init()
 }
}

fn finish_init(&mut self) -> SECStatus {
unsafe {
  nss_cmd(|| NSS_SetDomesticPolicy());
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
    let path = &Path::init(file);
    let mut retStatus = SECFailure;
    if(!path.exists()){ return retStatus; }
    io_error::cond.trap(|_| { retStatus = SECFailure; }).inside(
    ||
      unsafe
      {
        let pemdata = str::from_utf8_owned(File::open(path).read_to_end());
        let cert = CERT_DecodeCertFromPackage(pemdata.to_c_str().unwrap(), pemdata.to_c_str().len() as i32);
        let trust = CERTCertTrust { sslFlags: 0, emailFlags: 0, objectSigningFlags: 0 };
        CERT_DecodeTrustString(&trust, "TCu,Cu,Tu".to_c_str().unwrap());
        retStatus = CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), cert, &trust);
      }
    );
    retStatus
}

}

pub fn nss_cmd(blk: || -> SECStatus) {
    let result = blk();
    if(result == SECFailure) {
      fail!("NSS Failed with {}", get_nss_error());
    }
}

pub fn get_nss_error() -> ~str {
    unsafe { 
        let err = PR_GetError();
        let name = PR_ErrorToName(err);
        if(name != ptr::null()) {
        std::str::raw::from_c_str(name)
        } else {
            ~"Unknown Error"
        }
    }
}
