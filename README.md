# goewf

goewf is a golang binding for the libewf project.  Read access support only.  No warranty offerred or implied, please validate if using in an evidentiary context.

# Build for ubuntu

## Install Go

sudo add-apt-repository ppa:gophers/archive
sudo apt-get update
sudo apt-get install golang-1.10-go

## Build libewf

git clone https://github.com/libyal/libewf
sudo apt install autoconf automake autopoint libtool pkg-config bison flex

cd libewf/
./synclibs.sh
./autogen.sh
./configure
./make

