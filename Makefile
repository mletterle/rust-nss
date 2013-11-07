nspr:
	rustc --lib rust-nspr/nspr/lib.rs
nss: 
	rustc --lib nss/lib.rs -L rust-nspr/nspr 
nss-test: nspr
	rustc --test nss/lib.rs -L rust-nspr/nspr -o nss/nss-test
all: nspr nss nss-test
test: nss-test
	cd nss;./nss-test
