use super::SECSuccess;
use std::rt::io::net::ip::{SocketAddr, Ipv4Addr};
use super::{ssl_connect, NSS};

#[test]
fn test_init() {
  // let mut nss = NSS::new();
 //  assert_eq!(nss.init(), SECSuccess);
 //  nss.uninit();
}

#[test]
fn test_ssl_connect(){
    let mut nss = NSS::new();
    nss.init();
    let mut sslstream = ssl_connect(SocketAddr { ip: Ipv4Addr(127, 0, 0, 1), port: 1234 }, ~"localhost");
    sslstream.write([116, 101, 115, 116]);
    nss.uninit();
}
