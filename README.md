# goewf

goewf is a golang binding for the libewf project.  Read access support only.  No warranty offerred or implied, please validate if using in an evidentiary context.

# Build for ubuntu

## Install Go

```
sudo add-apt-repository ppa:gophers/archive
sudo apt-get update
sudo apt-get install golang-1.10-go
```

## Clone, build libewf, run sample

```
sudo apt install autoconf automake autopoint libtool pkg-config bison flex

go get -u github.com/sydp/goewf

cd libewf/
./synclibs.sh
./autogen.sh
./configure
./make

go build -o goewf cmd/goewf/main.go

# Read the first 512 bytes from image.E01
goewf image.E01 512
```
