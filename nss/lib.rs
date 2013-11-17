#[link(name = "nss", vers = "0.0-pre")];
#[feature(struct_variant)];
#[feature(globs)];

extern mod nspr;

extern mod extra;

pub mod nss;
pub mod ssl;


