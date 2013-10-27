use ffi::SECSuccess;
use super::init;

#[test]
fn test_init() {
   assert_eq!(init(), SECSuccess);
}
