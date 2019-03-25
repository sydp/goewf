package main

import (
	"os"
    "github.com/sydp/goewf/ewf"
	"fmt"
	"strconv"
)

func main() {

	if len(os.Args) != 3 {
		println("Usage: goewf <filename> <bytes_To_read>")
		return
	}

	var ewfFilename = os.Args[1]
	var amountToRead, _ = strconv.Atoi(os.Args[2])
	var filenames, err = ewf.Glob(ewfFilename)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Found %d file(s) for %s\n", len(filenames), ewfFilename)
	for _, filename := range filenames {
		println(filename)
	}

	var handle ewf.EwfHandle

	if err = handle.Init(); err != nil {
		fmt.Println(err)
		return
	}
	defer handle.Free()

	var readAccessFlags = ewf.GetAccessFlagsRead()
	if err = handle.Open(filenames, readAccessFlags); err != nil {
		fmt.Println(err)
		return
	}
	defer handle.Close()

	var buffer = make([]byte, amountToRead)
	amountRead, err := handle.Read(amountToRead, &buffer)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%d bytes read - %x\n", amountRead, buffer)

	rootEntry, err := handle.GetRootFileEntry()
	if err != nil {
		fmt.Println(err)
		return
	}

	if !rootEntry.IsValid() {
		fmt.Println("No root entry found")
		return
	}

	rootName, err := rootEntry.GetName()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Root entry - %s\n", rootName)
}