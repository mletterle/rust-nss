use std::libc::{c_char, c_int, c_void, c_ulong, c_uint, c_short, c_ushort};

//TODO: Refactor all of the nspr stuff into its own library.. soon.

#[link_args = "-lnss3 -lnspr4 -lssl3"]
#[nolink]
extern "C" { }

pub type SECStatus = c_int;
pub type PRBool = c_int;
pub type PRStatus = c_int;


pub static SECSuccess: c_int = 0;
pub static SECFailure: c_int = -1;
pub static SECWouldBlock: c_int = -2;

pub static PRTrue: PRBool = 1;
pub static PRFalse: PRBool = 0;

pub static PRSuccess: PRStatus = 0;
pub static PRFailure: PRStatus = -1;

pub static PR_AF_INET: c_ushort = 2;

pub static NSS_INIT_READONLY: c_uint = 0x1;
pub static NSS_INIT_PK11RELOAD: c_uint = 0x80;

pub static SSL_ENABLE_SSL2: c_int = 7;
pub static SSL_V2_COMPATIBLE_HELLO: c_int = 12;
pub static SSL_ENABLE_DEFLATE: c_int = 19;
pub static SSL_EN_DES_192_EDE3_CBC_WITH_MD5: c_int = 65287;
pub static SSL_ALLOWED: c_int = 1;
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


pub struct PRNetAddr {
     family: c_ushort,
     port: c_ushort,
     ip: c_uint,
     pad: [c_char, ..8],

}


pub static TLS_RSA_WITH_AES_128_CBC_SHA: c_int = 0x002f;

externfn!(fn NSS_Init(configdir: *c_char) -> SECStatus)
externfn!(fn NSS_NoDB_Init(configdir: *c_char) -> SECStatus)
externfn!(fn NSS_InitContext(configdir: *c_char, certPrefix: *c_char, keyPrefix: *c_char, secmodName: *c_char, initStrings: *c_void, flags: c_uint) -> *c_void)
externfn!(fn NSS_ShutdownContext(ctx: *c_void))
externfn!(fn NSS_SetDomesticPolicy() -> SECStatus)
externfn!(fn SECMOD_DestroyModule(module: *SECMODModule))
externfn!(fn SECMOD_LoadUserModule(moduleSpec: *c_char, parent: *SECMODModule, recurse: PRBool) -> *SECMODModule)
externfn!(fn PR_OpenTCPSocket(af: c_ushort) -> *c_void)
externfn!(fn PR_Connect(fd: *c_void, addr: *PRNetAddr, timout: c_uint) -> PRStatus)
externfn!(fn PR_Close(fd: *c_void) -> PRStatus)
externfn!(fn PR_StringToNetAddr(string: *c_char, addr: *c_void) -> PRStatus)
externfn!(fn PR_GetError() -> c_int)
externfn!(fn PR_ErrorToName(error: c_int) -> *c_char)
externfn!(fn PR_htons(conversion: c_ushort) -> c_ushort)
externfn!(fn PR_htonl(conversion: c_uint) -> c_uint)
externfn!(fn SSL_ImportFD(model: *c_void, fd: *c_void) -> *c_void)
externfn!(fn SSL_OptionSet(fd: *c_void, option: c_int, on: PRBool) -> SECStatus)
externfn!(fn SSL_ResetHandshake(fd: *c_void, asServer: PRBool) -> SECStatus)
externfn!(fn SSL_ForceHandshake(fd: *c_void) -> SECStatus)
externfn!(fn SSL_SetURL(fd: *c_void, url: *c_char) -> c_int)
externfn!(fn SSL_CipherPolicySet(cipher: c_int, policy: c_int) -> SECStatus)
externfn!(fn PR_Write(fd: *c_void, buf: *c_void, amount: c_int) -> c_int)
externfn!(fn PR_Read(fd: *c_void, buf: *c_void, amount: c_int) -> c_int)

