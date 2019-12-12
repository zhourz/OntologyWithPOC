package poc

/*
#cgo LDFLAGS: -L. -lshabal
#include "shabal.h"
*/
import "C"
import (
	"OntologyWithPOC/common/log"
)

func Callshabal(name string, buff1 []byte, buff2 []byte, buff3 []byte, buff4 []byte, buff5 []byte) {
	if name == "shabal256" {
		C.shabal256(C.CString(string(buff1)), C.CString(string(buff2)))
	} else if name == "shabal512" {
		C.shabal512(C.CString(string(buff1)), C.CString(string(buff2)))
	} else if name == "genNonce256" {
		C.genNonce256(C.CString(string(buff1)), C.CString(string(buff2)), C.CString(string(buff5)))
	} else if name == "genNonce512" {
		C.genNonce512(C.CString(string(buff1)), C.CString(string(buff2)), C.CString(string(buff5)))
	} else if name == "genHash_Target256" {
		C.genHash_Target256(C.CString(string(buff1)), C.CString(string(buff2)), C.CString(string(buff3)), C.CString(string(buff4)), C.CString(string(buff5)))
	} else if name == "genHash_Target512" {
		C.genHash_Target512(C.CString(string(buff1)), C.CString(string(buff2)), C.CString(string(buff3)), C.CString(string(buff4)), C.CString(string(buff5)))
	} else {
		log.Errorf("please input 256 or 512 for the first per!")
	}
}
