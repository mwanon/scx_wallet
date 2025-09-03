package structs

import (
	"encoding/binary"
	"github.com/mwanon/scx_node/structs"
)

const OUTPUTSIZE = int64(40)

type TransactionOutput struct { //  112 bytes
	Address [32]byte //32 bytes
	Amount  int64    //8 bytes
}

func (to *TransactionOutput) ToBytes() ([]byte, error) {
	TOLen := to.GetLength()
	tran := make([]byte, TOLen)

	copy(tran[0:], to.Address[:])
	_ = binary.PutVarint(tran[32:], to.Amount)
	//binary.BigEndian.PutUint64(tran[32:],  uint64(to.Amount))
	return tran[:], nil
}

func (to *TransactionOutput) ToJSON(OutputBytes []byte) error {
	//var intVal int64

	pos := 0
	copy(to.Address[pos:], OutputBytes[pos:pos+32])
	intVal, l := binary.Varint(OutputBytes[pos:])
	to.Amount = intVal
	pos = pos + l

	return nil
}

func (to *TransactionOutput) GetLength() int64 {
	var junk [8]byte
	pos := 32
	l := binary.PutVarint(junk[0:], to.Amount)
	pos = pos + l
	return int64(pos)
}

func (to *TransactionOutput) AddAddressBytes(AddressBytes []byte) error {
	copy(to.Address[0:], AddressBytes[:])
	return nil
}

func (to *TransactionOutput) AddAddressString(AddressString string) error {
	var addr structs.Address
	err := addr.LoadPublicAddress(AddressString)
	copy(to.Address[0:], addr.PublicBytes[:])
	return err
}

func (to *TransactionOutput) AddAmount(Amount int64) error {
	to.Amount = Amount
	return nil
}
