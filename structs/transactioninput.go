package structs

import (
	"encoding/binary"
	"github.com/mwanon/scx_node/structs"
	"fmt"
)

const INPUTSIZE = int64(112)

type TransactionInput struct { //  112 bytes
	Address        [32]byte //32 bytes
	Amount         int64    // (this is a varint when in byte format)
	Timestamp      int64    // (this is a varint when in byte format)
	SignatureBytes [64]byte //64 bytes
}

func (ti *TransactionInput) ToBytes() ([]byte, error) {
	var TILen int64
	TILen = ti.GetLength()
	tran := make([]byte, TILen)
	var pos = 0
	copy(tran[pos:], ti.Address[:])
	pos = pos + 32
	l := binary.PutVarint(tran[pos:], ti.Amount)
	pos = pos + l
	l = binary.PutVarint(tran[pos:], ti.Timestamp)
	pos = pos + l
	copy(tran[pos:], ti.SignatureBytes[:])
	return tran[:], nil
}

func (ti *TransactionInput) GetLength() int64 {
	var junk [32]byte
	var pos = 0

	pos = pos + 32 // address
	l := binary.PutVarint(junk[0:], ti.Amount)
	pos = pos + l
	l = binary.PutVarint(junk[0:], ti.Timestamp)
	pos = pos + l
	pos = pos + 64 // signature
	return int64(pos)
}

func (ti *TransactionInput) ToJSON(InputBytes []byte) error {
	//var intVal int64

	pos := 0
	copy(ti.Address[pos:], InputBytes[pos:pos+32])
	intVal, l := binary.Varint(InputBytes[pos:])
	ti.Amount = intVal
	pos = pos + l
	intVal, l = binary.Varint(InputBytes[pos:])
	ti.Timestamp = intVal
	pos = pos + l
	copy(ti.SignatureBytes[0:], InputBytes[pos:])

	return nil
}

func (ti *TransactionInput) AddAddressBytes(AddressBytes []byte) error {
	copy(ti.Address[0:], AddressBytes[:])
	return nil
}

func (ti *TransactionInput) AddAddressString(AddressString string) error {
	var addr structs.Address
	err := addr.LoadPublicAddress(AddressString)
	copy(ti.Address[0:], addr.PublicBytes[:])
	return err
}

func (ti *TransactionInput) AddAmount(Amount int64) error {
	ti.Amount = Amount
	return nil
}

func (ti *TransactionInput) AddTimestamp(millitime int64) error {
	ti.Timestamp = millitime
	return nil
}

func (ti *TransactionInput) AddSignature(Signature []byte) error {
	copy(ti.SignatureBytes[0:], Signature[:])
	return nil
}

func (ti *TransactionInput) BytesToSign() ([]byte, error) {
	var TILen int64
	TILen = ti.GetLength()
	tran := make([]byte, TILen)
	var pos = 0
	copy(tran[pos:], ti.Address[:])
	pos = pos + 32
	l := binary.PutVarint(tran[pos:], ti.Amount)
	pos = pos + l
	l = binary.PutVarint(tran[pos:], ti.Timestamp)
	pos = pos + l
	fmt.Println("pos")
	fmt.Println(pos)


	// with the byte variant for amount and timestamp,
	//   the response is shorter than TILen

	ReturnBytes := make([]byte, pos)
	copy(ReturnBytes[0:], tran[0:pos])
	return ReturnBytes[:], nil
}
