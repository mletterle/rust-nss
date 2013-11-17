nspr:
	rustc --lib rust-nspr/nspr/lib.rs
nss: nspr
	rustc --lib nss/lib.rs -L rust-nspr/nspr 
nss-test: nss
	rustc --test nss/tests/nss-tests.rs -L rust-nspr/nspr -L nss
all: nspr nss nss-test
test: nss-test
	cd nss/tests;./nss-tests
