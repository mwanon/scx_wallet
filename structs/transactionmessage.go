package structs

import "encoding/binary"

type TransactionMessage struct {
	Key   []byte
	Value []byte
}

func (tm *TransactionMessage) ToBytes() ([]byte, error) {
	var jnk [8]byte
	var tmLen int
	tmLen = int(tm.GetLength())

	tmBytes := make([]byte, tmLen)

	cur := 0

	tmLen = binary.PutVarint(jnk[:], int64(len(tm.Key)))

	copy(tmBytes[cur:], jnk[:])
	cur = cur + tmLen

	copy(tmBytes[cur:], tm.Key[:])
	cur = cur + len(tm.Key)

	tmLen = binary.PutVarint(jnk[:], int64(len(tm.Value)))

	copy(tmBytes[cur:], jnk[:])
	cur = cur + tmLen

	copy(tmBytes[cur:], tm.Value[:])
	cur = cur + len(tm.Value)

	return tmBytes[:], nil
}

func (tm *TransactionMessage) GetLength() int64 {
	var jnk [8]byte
	var tmLen int
	tmLen = 0

	tmLen = tmLen + len(tm.Key)
	tmLen = tmLen + len(tm.Value)

	tmLen = tmLen + binary.PutVarint(jnk[:], int64(len(tm.Key)))
	tmLen = tmLen + binary.PutVarint(jnk[:], int64(len(tm.Value)))

	return int64(tmLen)
}
