#[link(name = "nss", vers = "0.0-pre")];
#[feature(struct_variant)];
#[feature(globs)];

extern mod nspr;

extern mod extra;

#[cfg(test)]
mod tests;

pub mod nss;
pub mod ssl;


