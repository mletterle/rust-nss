extern mod nss;

use nss::nss::{NSS, get_nss_error};
use nss::nss::raw::{SECSuccess, SECFailure, SSLBadCertHandler};
use std::io::net::ip::{SocketAddr, Ipv4Addr};
use nss::ssl::{SSLStream};


#[test]
fn test_init() {
   let mut nss = NSS::new();
   let result = nss.init();
   if(result != SECSuccess) { println(format!("NSS Failed with {}", get_nss_error())) };
   assert_eq!(result, SECSuccess);
   nss.uninit();
}

#[test]
fn test_ssl_connect_with_trusted_cert(){
    let mut nss = NSS::new();
    nss.nodb_init();
    nss::nss::nss_cmd(|| NSS::trust_cert(~"files/testcert.pem"));
    let mut sslstream =  SSLStream::connect(SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: 1234 }, ~"localhost");
    sslstream.write(bytes!("Hello SSL\n"));
    sslstream.disconnect();
    nss.uninit();
}

#[test]
fn test_ssl_badcert_callback() {
    let mut nss = NSS::new();
    nss.init();
    let badcert_hook: SSLBadCertHandler = proc(arg, fd){ SECSuccess };
    let mut sslstream =  SSLStream::connect_opt(SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: 1234 }, ~"wronglocalhost", Some(badcert_hook));
    sslstream.write(bytes!("Hello SSL\n"));
    sslstream.disconnect();
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
    let import = NSS::trust_cert(~"files/testcert.pem");
    assert_eq!(import, SECSuccess);
    nss.uninit();
}

