use super::{SECSuccess, SECFailure};
use std::rt::io::net::ip::{SocketAddr, Ipv4Addr};
use super::NSS;

#[test]
fn test_init() {
   let mut nss = NSS::new();
   assert_eq!(nss.init(), SECSuccess);
   nss.uninit();
}

#[test]
fn test_ssl_connect(){
    let mut nss = NSS::new();
    nss.init();
    do super::nss_cmd { NSS::trust_cert(~"tests/files/testcert.pem") };
    let mut sslstream =  NSS::ssl_connect(SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: 1234 }, ~"localhost");
    sslstream.write(bytes!("Hello SSL\n"));
    nss.uninit();
}

#[test]
fn test_set_cfg_dir() {
    let mut nss = NSS::new();
    nss.set_cfg_dir("testdir");
    let cfgdir = match nss.cfg_dir {
        Some(ref s) => s.to_owned(),
        None => ~"Unknown!",
    };
    assert_eq!(cfgdir, ~"testdir");
}

#[test]
fn test_trust_cert_with_invalid_path() {
    let mut nss = NSS::new();
    nss.init();
    let import = NSS::trust_cert(~"blahblahblah");
    assert_eq!(import, SECFailure);
    nss.uninit();
}

#[test]
fn test_trust_cert_with_valid_path() {
    let mut nss = NSS::new();
    nss.init();
    let import = NSS::trust_cert(~"tests/files/testcert.pem");
    assert_eq!(import, SECSuccess);
    nss.uninit();
}

