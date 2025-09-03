package common

import (
	"crypto/sha256"
	"time"
)

func UnixMilli() int64 {
	return time.Now().UnixNano() / 1000000
}

// addand hash concatenates two binary slices then
// hashes them.

func AddAndHash(first []byte, second []byte) [32]byte {
	both := make([]byte, len(first)+len(second))
	copy(both[0:], first[:])
	copy(both[len(first):], second[:])

	hash := sha256.Sum256(both)
	return hash
}

var COUNTDIFFICULTYAVERAGE = int64(5)
var ZerosBytes [32]byte
var AllFsBytes [32]byte

func Init() {
	i := 0
	for i < 32 {
		ZerosBytes[i] = 0x00
		i = i + 1
	}
	i = 0
	for i < 32 {
		AllFsBytes[i] = 0xff
		i = i + 1
	}

}
