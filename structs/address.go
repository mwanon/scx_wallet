package structs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"encoding/json"
	"crypto/ed25519"
	"github.com/btcsuitereleases/btcutil/base58"
	"bytes"
)

type Address struct {
	PrivateBytes    [32]byte // hex bytes
	PrivateReadable string
	PublicBytes     [32]byte // hex bytes
	PublicReadable  string
}

type BalanceRequest struct {
	PublicAddress string `json:"publicaddress"`
	Balance       int64  `json:"balance"`
}

func (a *Address) LoadPublicAddress(ReadableAddress string) error {
	if ReadableAddress[0:3] != "SCX" {
		errors.New("Invalid Address.")
	}
	a.PublicReadable = ReadableAddress

	val, err := ReadablePublicToBytes(ReadableAddress)
	if err != nil {
		return err
	}
	copy(a.PublicBytes[0:], val)

	return err
}

func (a *Address) LoadBytesPublic() error {

	if len(a.PublicBytes) < 32 {
		return errors.New("Address Too Short.")
	}
	
	AddressString := BytesToReadablePublic(a.PublicBytes[:])
	if AddressString == "" {
		return errors.New("Invalid Address.")
	}
	a.PublicReadable = AddressString

	return nil
}

func (a *Address) LoadPrivateAddress(ReadableAddress string) error {
	if ReadableAddress[0:3] != "SCS" {
		errors.New("Invalid Address.")
	}
	a.PrivateReadable = ReadableAddress

	val, err := ReadablePrivateToBytes(ReadableAddress)
	if err != nil {
		return err
	}
	pk := ed25519.NewKeyFromSeed(val)
	pKey := make([]byte,32)
	copy(pKey,pk[32:])
	sd := pk.Seed()
	copy (a.PrivateBytes[0:], sd[:])
	copy (a.PublicBytes[0:] ,pKey[:])
	a.LoadBytesPublic()
	return err
}

func (a *Address) LoadBytesPrivate(PrivateBytes []byte) error {

	if len(PrivateBytes) < 32 {
		return errors.New("Address Too Short.")
	}
	copy(a.PrivateBytes[0:], PrivateBytes[:])
	AddressString := BytesToReadablePrivate(PrivateBytes[:])
	if AddressString == "" {
		return errors.New("Invalid Address.")
	}
	a.PrivateReadable = AddressString
	
	pk := ed25519.NewKeyFromSeed(PrivateBytes)
	pubKey := make([]byte,32)
	copy(pubKey,pk[32:])
	copy(a.PrivateBytes[0:], PrivateBytes)
	copy(a.PublicBytes[0:], pubKey)
	a.LoadBytesPublic()
	return nil
}



func ReadablePublicToBytes(ReadableAddress string) ([]byte, error) {
	var AddressBytes [32]byte
	var cutCheckSum [35]byte
	var hash [32]byte

	if ReadableAddress[0:3] != "SCX" {
		return nil, errors.New("Bad Public Address Prefix")
	}
	str256 := base58.Decode(ReadableAddress)
	copy(cutCheckSum[0:], str256[0:35])
	hash = sha256.Sum256(cutCheckSum[:])
	//fmt.Println("checksum test")
	//fmt.Println(str256[35:])
	//fmt.Println(hash[28:])
	
	if !reflect.DeepEqual(str256[35:], hash[28:]) {
		return nil, errors.New("Bad Public Address - Checksum")
	}
	copy(AddressBytes[0:], cutCheckSum[3:35])

	return AddressBytes[:], nil
}

func ReadablePrivateToBytes(ReadableAddress string) ([]byte, error) {
	var AddressBytes [32]byte
	var cutCheckSum [35]byte
	var hash [32]byte

	if ReadableAddress[0:3] != "SCS" {
		return nil, errors.New("Bad Public Address")
	}
	str256 := base58.Decode(ReadableAddress)
	copy(cutCheckSum[0:], str256[0:35])
	hash = sha256.Sum256(cutCheckSum[:])

	if !reflect.DeepEqual(str256[35:], hash[28:]) {
		return nil, errors.New("Bad Public Address - Checksum")
	}
	copy(AddressBytes[0:], cutCheckSum[3:35])

	return AddressBytes[:], nil
}


func BytesToReadablePublic(PublicBytes []byte) string {
	var prefixBytes [35]byte
	var AddressBytes [39]byte
	if len(PublicBytes) < 32 {
		return ""
	}
	prefixBytes[0]=0x26
	prefixBytes[1]=0x97
	prefixBytes[2]=0xe9

	copy(prefixBytes[3:], PublicBytes)

	hash := sha256.Sum256(prefixBytes[:])

	copy(AddressBytes[0:], prefixBytes[:])
	copy(AddressBytes[35:], hash[28:])

	b58Bytes := base58.Encode(AddressBytes[:])

	return b58Bytes
}

func BytesToReadablePrivate(PrivateBytes []byte) string {
	var prefixBytes [35]byte
	var AddressBytes [39]byte
	if len(PrivateBytes) < 32 {
		return ""
	}
	prefixBytes[0]=0x26
	prefixBytes[1]=0x97
	prefixBytes[2]=0x54

	copy(prefixBytes[3:], PrivateBytes)

	hash := sha256.Sum256(prefixBytes[:])

	copy(AddressBytes[0:], prefixBytes[:])
	copy(AddressBytes[35:], hash[28:])

	b58Bytes := base58.Encode(AddressBytes[:])
fmt.Println(b58Bytes)
	return b58Bytes
}
func GetBalance(NodeURL string,publicaddress string) int64 {
	fmt.Println("GetBalance")
	fmt.Println(NodeURL)
	var bReq BalanceRequest
	bReq.PublicAddress = publicaddress
	rBytes, err := json.Marshal(bReq)

	resp, err := http.Post(NodeURL+"/transaction", "application/json", bytes.NewBuffer([]byte(rBytes)))
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal(body, &bReq)

	if err == nil {
		balance := bReq.Balance
		return balance
	}
	return 0

}

