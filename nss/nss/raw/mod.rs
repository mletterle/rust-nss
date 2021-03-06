extern mod nspr;

use std::libc::{c_char, c_int, c_void, c_ulong, c_uint};
pub use nspr::raw::nspr::*;

pub type SECStatus = c_int;


pub static SECSuccess: c_int = 0;
pub static SECFailure: c_int = -1;
pub static SECWouldBlock: c_int = -2;


pub static NSS_INIT_READONLY: c_uint = 0x1;
pub static NSS_INIT_PK11RELOAD: c_uint = 0x80;

pub static SSL_ENABLE_SSL2: c_int = 7;
pub static SSL_V2_COMPATIBLE_HELLO: c_int = 12;
pub static SSL_ENABLE_DEFLATE: c_int = 19;
pub static SSL_EN_DES_192_EDE3_CBC_WITH_MD5: c_int = 65287;
pub static SSL_ALLOWED: c_int = 1;
pub static TLS_RSA_WITH_AES_128_CBC_SHA: c_int = 0x002f;

pub struct SECMODModule {    
    arena: *c_void, //TODO
    internal: PRBool,	/* true of internally linked modules, false for the loaded modules */
    loaded: PRBool,	/* Set to true if module has been loaded */
    isFIPS: PRBool,		/* Set to true if module is finst internal */
    dllName: *c_char,	/* name of the shared library which implements this module */
    commonName: *c_char, /* name of the module to display to the user */
    library: *c_void,	/* pointer to the library. opaque. used only by pk11load.c */
    functionList: *c_void, /* The PKCS #11 function table */
    refLock: *c_void,	/* only used pk11db.c */
    refCount: c_int,	/* Module reference count */
    slots: **c_void,//TODO	/* array of slot points attached to this mod*/
    slotCount: c_int,	/* count of slot in above array */
    slotInfo: *c_void,//TODO	/* special info about slots default settings */
    slotInfoCount: c_int,  /* count */
    moduleID: c_ulong,	/* ID so we can find this module again */
    isThreadSafe: PRBool,
    ssl: [c_ulong, ..2],	/* SSL cipher enable flags */
    libraryParams: *c_char,  /* Module specific parameters */
    moduleDBFunc: *c_void, /* function to return module configuration data*/
    parent: *SECMODModule,	/* module that loaded us */
    isCritical: PRBool,	/* This module must load successfully */
    isModuleDB: PRBool,	/* this module has lists of PKCS #11 modules */
    moduleDBOnly: PRBool,	/* this module only has lists of PKCS #11 modules */
    trustOrder: c_int,	/* order for this module's certificate trust rollup */
    cipherOrder: c_int,	/* order for cipher operations */
    evControlMask: c_ulong, /* control the running and shutdown of slot events (SECMOD_WaitForAnyTokenEvent) */
    cryptokiVersion: CK_VERSION, /* version of this library */
}


pub struct CK_VERSION {
    major: c_uint,
    minor: c_uint,
}

pub enum SECCertUsage {
  SSLClient = 0,
  SSLServer = 1,
  SSLServerWithStepUp = 2,
  SSLCA = 3,
  EmailSigner = 4,
  EmailRecipient = 5,
  ObjectSigner = 6,
  UserCertImport = 7,
  UsageVerifyCA = 8,
  ProtectedObjectSigner = 9,
  StatusResponder = 10,
  AnyCA = 11,
}

pub enum SECItemType {
    Buffer = 0,
    ClearDataBuffer = 1,
    CipherDataBuffer = 2,
    DERCertBuffer = 3,
    EncodedCertBuffer = 4,
    DERNameBuffer = 5,
    EncodedNameBuffer = 6,
    AsciiNameString = 7,
    AsciiString = 8,
    DEROID = 9,
    UnsignedInteger = 10,
    UTCTime = 11,
    GeneralizedTime = 12,
    VisibleString = 13,
    UTF8String = 14,
    BMPString = 15,
}

pub struct SECItem {
    sectype: SECItemType,
    data: *c_char,
    len: c_uint,
}

pub struct CERTCertTrust {
    sslFlags: c_int,
    emailFlags: c_int,
    objectSigningFlags: c_int,
}

pub type SSLBadCertHandler = proc(arg: *c_void, fd: *c_void) -> SECStatus;

#[link_args = "-lnss3 -lssl3 -lsmime3"]
extern "C" {
pub fn NSS_Init(configdir: *c_char) -> SECStatus;
pub fn NSS_NoDB_Init(configdir: *c_char) -> SECStatus;
pub fn NSS_InitContext(configdir: *c_char, certPrefix: *c_char, keyPrefix: *c_char, secmodName: *c_char, initStrings: *c_void, flags: c_uint) -> *c_void;
pub fn NSS_IsInitialized() -> PRBool;
pub fn NSS_ShutdownContext(ctx: *c_void);
pub fn NSS_SetDomesticPolicy() -> SECStatus;

pub fn SECMOD_DestroyModule(module: *SECMODModule);
pub fn SECMOD_LoadUserModule(moduleSpec: *c_char, parent: *SECMODModule, recurse: PRBool) -> *SECMODModule;

pub fn SSL_ImportFD(model: *c_void, fd: *c_void) -> *c_void;
pub fn SSL_OptionSet(fd: *c_void, option: c_int, on: PRBool) -> SECStatus;
pub fn SSL_ResetHandshake(fd: *c_void, asServer: PRBool) -> SECStatus;
pub fn SSL_ForceHandshake(fd: *c_void) -> SECStatus;
pub fn SSL_SetURL(fd: *c_void, url: *c_char) -> c_int;
pub fn SSL_CipherPolicySet(cipher: c_int, policy: c_int) -> SECStatus;
pub fn SSL_BadCertHook(fd: *c_void,  callback_fn: SSLBadCertHandler, arg: *c_void) -> SECStatus;

pub fn CERT_GetDefaultCertDB() -> *c_void;
pub fn CERT_DecodeCertFromPackage(certbuf: *c_char, certlen: c_int) -> *c_void;
pub fn CERT_DecodeTrustString(trust: *CERTCertTrust, trusts: *c_char) -> SECStatus;
pub fn CERT_ChangeCertTrust(certdb: *c_void, cert: *c_void, trust: *CERTCertTrust) -> SECStatus;
}
