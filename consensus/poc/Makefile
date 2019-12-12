ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

build:
	cd ./shabal && cargo build --release
ifeq ($(shell uname), Linux)
	cp ./shabal/target/release/libshabal.so ../../
	cp ./shabal/target/release/libshabal.so ./
else ifeq ($(shell uname), Darwin)
	cp ./shabal/target/release/libshabal.dylib ../../
	cp ./shabal/target/release/libshabal.dylib ./
else ifeq ($(shell ver), Microsoft Windows)
    cp ./shabal/target/release/shabal.dll ./
endif
	go build -ldflags="-r $(ROOT_DIR)" shabal.go

run: build
	./shabal
