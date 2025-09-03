package structs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"

	//"github.com/mwanon/scx_wallet/state"
	//"github.com/mwanon/scx_wallet/structs"
	"crypto"
	"crypto/rand"

	
	"crypto/ed25519"
	//ed "github.com/FactomProject/ed25519"
	"github.com/mwanon/scx_wallet/common"
)

// transaction input bytes definition
// TransactionID [32]byte
// InputCount [2]byte
// loop inputs
// 	Inputs [InputCount*80 bytes]
// end input loop
// InputHash [32]byte
// OutputCount [2]byte
// Outputs [OutputCount*80 bytes]
// outputHash [32]byte
// messageCount [1]byte
// messages loop
//   messagelength [3]byte   // message length can be up to 4096
//   messagebytes [messagelength]
//   messagehash [32]byte
// end message loop
// timestamp [8]byte
// Signature [32]byte

type Transaction struct {
	TransactionID      []byte
	Inputs             []TransactionInput
	InputsHash         []byte
	Outputs            []TransactionOutput
	OutputsHash        []byte
	Messages           []TransactionMessage
	MessagesHash       []byte
	Timestamp          int64
	Signatures         []TransactionSignature
	RequiredSignatures int64
}

type TransactionRequest struct {
	TransactionHash string `json:"transactionhash"`
	PublicAddress   string `json:"address"`
}

type TransactionResponse struct {
	TransactionID string `json:"transactionhash"`
	Status        string `json:"status"`
	Timestamp     int64  `json:"timestamp"`
}

var SIGNATURESIZE = 96

type TransactionSignature struct {
	SignatureAddress [32]byte
	SignatureBytes   [64]byte
}

func (t *Transaction) GetLength() int64 {

	var jnk [8]byte
	var i int
	ln := int64(0)
	ln = ln + 32 //transactionhid (hash)

	ln = ln + int64(binary.PutVarint(jnk[:], int64(len(t.Inputs)))) // input count bytes
	for _, i := range t.Inputs {
		ln = ln + i.GetLength()
	}
	ln = ln + 32

	//ln = ln + int64(len(t.Inputs)) * INPUTSIZE
	// inputhash
	ln = ln + int64(binary.PutVarint(jnk[:], int64(len(t.Outputs)))) // input count bytes
	i = 0

	for _, o := range t.Outputs {
		ln = ln + o.GetLength()
	}
	//ln = ln + int64(len(t.Outputs)) * OUTPUTSIZE
	ln = ln + 32 //outputhash

	i = 0
	ln = ln + int64(binary.PutVarint(jnk[:], int64(len(t.Messages)))) // input count bytes
	
	for _, m := range t.Messages {
		ln = ln + m.GetLength()
	}
	ln = ln + 32 //messageshash

	ln = ln + int64(binary.PutVarint(jnk[:], t.Timestamp))
	//required signatures
	ln = ln + int64(binary.PutVarint(jnk[:], t.RequiredSignatures))

	//ln = ln + 8 //timestamp length (int64)
	ln = ln + int64(binary.PutVarint(jnk[:], int64(len(t.Signatures))))
	i = 0
	for i < len(t.Signatures) {
		ln = ln + int64(len(t.Signatures[i].SignatureAddress))
		ln = ln + int64(len(t.Signatures[i].SignatureBytes)) // message length count bytes)
		//ln = ln + int64(SIGNATURESIZE)
		i = i + 1
	}

	return int64(ln)
}

func (t *Transaction) ToBytes() []byte {

	bLength := t.GetLength()
	tBytes := make([]byte, bLength)

	pos := 0
	copy(tBytes[pos:pos+32], t.TransactionID)
	pos = pos + 32
	// number of inputs

	pos = pos + int(binary.PutVarint(tBytes[pos:], int64(len(t.Inputs))))
	i := 0
	for i < len(t.Inputs) {
		inpBytes, err := t.Inputs[i].ToBytes()
		if err != nil {
			fmt.Println(err)
		}
		copy(tBytes[pos:], inpBytes)
		pos = pos + len(inpBytes)
		i = i + 1
	}
	//inputhash
	copy(tBytes[pos:pos+32], t.InputsHash)
	pos = pos + 32

	//outputs
	pos = pos + int(binary.PutVarint(tBytes[pos:], int64(len(t.Outputs))))

	i = 0
	for i < len(t.Outputs) {
		outBytes, err := t.Outputs[i].ToBytes()
		if err != nil {
			fmt.Println(err)
		}
		copy(tBytes[pos:], outBytes)
		pos = pos + len(outBytes)

		i = i + 1
	}

	//outputhash
	copy(tBytes[pos:pos+32], t.OutputsHash)
	pos = pos + 32

	pos = pos + int(binary.PutVarint(tBytes[pos:], int64(len(t.Messages))))

	i = 0

	for i < len(t.Messages) {
		msgBytes, err := t.Messages[i].ToBytes()

		if err != nil {
			fmt.Println("Message Error")
		}
		copy(tBytes[pos:pos+len(msgBytes)], msgBytes)
		pos = pos + len(msgBytes)

		i = i + 1
	}
	//messageshash

	if len(t.Messages) == 0 {
		copy(tBytes[pos:pos+32], common.ZerosBytes[:]) // hash has not been set.  0 fill
	} else {
		copy(tBytes[pos:pos+32], t.MessagesHash)
	}
	pos = pos + 32

	//timestamp
	pos = pos + int(binary.PutVarint(tBytes[pos:], t.Timestamp))

	// required signatures
	pos = pos + int(binary.PutVarint(tBytes[pos:], int64(len(t.Signatures))))
	// number of signatures
	pos = pos + int(binary.PutVarint(tBytes[pos:], int64(len(t.Signatures))))

	i = 0

	for i < len(t.Signatures) {
		if len(t.Signatures[i].SignatureAddress[:]) == 0 {
			copy(tBytes[pos:pos+32], common.ZerosBytes[:])
		} else {
			copy(tBytes[pos:pos+32], t.Signatures[i].SignatureAddress[:])
		}
		pos = pos + 32
		if len(t.Signatures[i].SignatureBytes[:]) == 0 {
			copy(tBytes[pos:pos+32], common.ZerosBytes[:]) // 64 byte fill
			copy(tBytes[pos+32:pos+64], common.ZerosBytes[:])
		} else {
			copy(tBytes[pos:pos+64], t.Signatures[i].SignatureBytes[:])
		}
		pos = pos + 64
		i++
	}

	return tBytes
}

func (t *Transaction) ToJSON(tBytes []byte) error {
	//var intVal int64

	l := 0

	pos := int64(0)
	// transaction input bytes definition
	t.TransactionID = tBytes[pos:32]
	pos = pos + 32

	cnt, p := binary.Varint(tBytes[pos:])
	pos = pos + int64(p)

	i := int64(0)
	// loop inputs

	for i < cnt {

		var inp TransactionInput
		copy(inp.Address[0:], tBytes[pos:pos+32])
		pos = pos + 32
		inp.Amount, l = binary.Varint(tBytes[pos:])
		pos = pos + int64(l)
		inp.Timestamp, l = binary.Varint(tBytes[pos:])
		pos = pos + int64(l)
		copy(inp.SignatureBytes[0:], tBytes[pos:pos+64])
		pos = pos + 64
		t.AddInput(inp)
		i = i + 1
	}
	//inputhash

	t.InputsHash = tBytes[pos : pos+32]

	pos = pos + 32

	cnt, p = binary.Varint(tBytes[pos:])

	pos = pos + int64(p)

	i = 0
	//loop outputs
	for i < cnt {
		var outp TransactionOutput
		copy(outp.Address[0:], tBytes[pos:pos+32])
		pos = pos + 32
		outp.Amount, l = binary.Varint(tBytes[pos:])
		pos = pos + int64(l)
		t.AddOutput(outp)
		i = i + 1
	}
	//output hash
	t.OutputsHash = tBytes[pos : pos+32]
	pos = pos + 32

	// Transaction Messages
	cnt, p = binary.Varint(tBytes[pos:])

	pos = pos + int64(p)
	i = 0

	for i < cnt {

		var msg TransactionMessage
		lng, p := binary.Varint(tBytes[pos:]) //field length
		pos = pos + int64(p)
		if int64(len(tBytes)) < pos+lng {
			return errors.New("Invalid Transaction Message Key Length.")
		}
		msg.Key = tBytes[pos : pos+lng]
		pos = pos + lng

		lng, p = binary.Varint(tBytes[pos:])
		pos = pos + int64(p)
		if int64(len(tBytes)) < pos+lng {
			return errors.New("Invalid Transaction Message Value Length.")
		}
		msg.Value = tBytes[pos : pos+lng]
		pos = pos + lng
		if int64(len(tBytes)) < pos+32 {
			return errors.New("Invalid Transaction Message Hash Length.")
		}
		//pos = pos + 32
		t.AddMessage(msg)
		i = i + 1
	}

	t.MessagesHash = tBytes[pos : pos+32]
	pos = pos + 32

	t.Timestamp, p = binary.Varint(tBytes[pos:])

	pos = pos + int64(p)

	t.RequiredSignatures, p = binary.Varint(tBytes[pos:])

	pos = pos + int64(p)
	//count of signature blocks
	cnt, p = binary.Varint(tBytes[pos:])

	pos = pos + int64(p)
	i = 0
	if len(tBytes) > int(pos) {

		for i < cnt {

			var Signat TransactionSignature
			copy(Signat.SignatureAddress[0:], tBytes[pos:pos+32])
			pos = pos + 32
			copy(Signat.SignatureBytes[0:64], tBytes[pos:pos+64])
			pos = pos + 64
			t.Signatures = append(t.Signatures, Signat)
			i = i + 1
		}
	}

	return nil
}

func (t *Transaction) AddInput(Input TransactionInput) error {
	inps := len(t.Inputs)
	templist := make([]TransactionInput, inps+1)
	i := 0
	for i < inps {
		templist[i] = t.Inputs[i]
		i = i + 1
	}
	templist[i] = Input
	t.Inputs = templist
	return nil
}

// sign it then call addinput
// signature is of
//    hash address
//    hash amoutn (as bigendian uint bytes)
//    hash timestamp
//    concatenate to 96 bytes
func (t *Transaction) AddSignedInput(privateKey []byte, Input TransactionInput) error {

	var lAddr Address
	lAddr.LoadBytesPrivate(privateKey)

	sigBytes, err := Input.BytesToSign()
	if err != nil {
		fmt.Println("Can't sign input")
	}

	priv := ed25519.NewKeyFromSeed(privateKey)

	Signat, err := priv.Sign(rand.Reader, sigBytes,crypto.Hash(0))

	if err != nil {
		fmt.Println("Signing Error",err)
	}

	copy(Input.SignatureBytes[:], Signat[:])
	t.AddInput(Input)

	return nil
}
func (t *Transaction) AddOutput(Output TransactionOutput) error {
	outs := len(t.Outputs)
	templist := make([]TransactionOutput, outs+1)
	i := 0
	for i < outs {
		templist[i] = t.Outputs[i]
		i = i + 1
	}
	templist[i] = Output
	t.Outputs = templist
	return nil
}
func (t *Transaction) AddMessage(Msg TransactionMessage) error {
	msgs := len(t.Messages)
	templist := make([]TransactionMessage, msgs+1)
	i := 0
	for i < msgs {
		templist[i] = t.Messages[i]
		i = i + 1
	}
	templist[i] = Msg
	t.Messages = templist
	return nil
}

func (t *Transaction) AddSignature(Signat TransactionSignature) error {

	sig := len(t.Signatures)
	templist := make([]TransactionSignature, sig+1)
	i := 0
	for i < sig {
		templist[i] = t.Signatures[i]
		i = i + 1
	}
	templist[i] = Signat
	t.Signatures = templist
	return nil
}

//TODO.
func (t *Transaction) CalculateFee() int64 {

	tBytes := t.ToBytes()
	tLen := int64(len(tBytes))
	// signatures and the fee input have not been added.  add their length to the fee calculation
	if t.RequiredSignatures == 0 {
		tLen = tLen + int64(SIGNATURESIZE)
	} else {
		tLen = tLen + t.RequiredSignatures*int64(SIGNATURESIZE)
	}
	//TODO.
	// inputsize is not correct here.  we store data as variants
	//  that means we will not have 2 8 byte numbers
	// for timestamp and amount.
	// fuzzy amount match in place now that needs to be accurate.
	tLen = tLen + INPUTSIZE
	return tLen
}

func (t *Transaction) VerifyFee() int64 {

	tBytes := t.ToBytes()
	tLen := int64(len(tBytes))
	return tLen
}

func (t *Transaction) HashInputs() error {
	// this is run once when all original inputs are added.
	// after adding fees
	// This has the entire first input
	// plus all but signature on other inputs as they may not be signed
	if len(t.Inputs) == 0 {
		return errors.New("Not Enough Inputs")
	}
	tHash := generateInputHash(t.Inputs)
	t.InputsHash = tHash[:]

	return nil
}

// first input is from the inputting address that is signign the transaction
// first mest be signed to its signature is part of the

func generateInputHash(inputs []TransactionInput) [32]byte {
	i := 0
	var tHash [32]byte
	var byteAmount [8]byte
	for i < len(inputs) {
		if i == 0 {
			tHash = sha256.Sum256(inputs[i].Address[:])
			//	binary.BigEndian.PutUint64(byteAmount, inputs[i].Amount)
			_ = binary.PutVarint(byteAmount[:], inputs[i].Amount)
			tHash = common.AddAndHash(tHash[:], inputs[i].Address[:])
			_ = binary.PutVarint(byteAmount[:], inputs[i].Timestamp)
			tHash = common.AddAndHash(tHash[:], byteAmount[:])
			tHash = common.AddAndHash(tHash[:], inputs[i].SignatureBytes[:])

		} else {
			tHash = common.AddAndHash(tHash[:], inputs[i].Address[:])
			_ = binary.PutVarint(byteAmount[:], inputs[i].Amount)
			tHash = common.AddAndHash(tHash[:], byteAmount[:])
			_ = binary.PutVarint(byteAmount[:], inputs[i].Timestamp)
			tHash = common.AddAndHash(tHash[:], byteAmount[:])

			// don't include signatures past originator
		}
		i = i + 1
	}

	return tHash
}

func (t *Transaction) HashOutputs() error {
	if len(t.Outputs) == 0 {
		return errors.New("Not Enough Outputs")
	}
	tHash := generateOutputHash(t.Outputs)
	t.OutputsHash = tHash[:]
	return nil
}

func generateOutputHash(outputs []TransactionOutput) [32]byte {
	i := 0
	var tHash [32]byte
	byteAmount := make([]byte, 8)
	for i < len(outputs) {
		if i == 0 {
			tHash = sha256.Sum256(outputs[i].Address[:])

		} else {
			tHash = common.AddAndHash(tHash[:], outputs[i].Address[:])
		}
		binary.PutVarint(byteAmount, outputs[i].Amount)
		tHash = common.AddAndHash(tHash[:], byteAmount)
		// don't include signatures past originator
		i = i + 1
	}
	return tHash
}

func (t *Transaction) HashMessages() error {
	if len(t.Inputs) == 0 {
		// no messages.   hash of 32 0s
		tH := sha256.Sum256(common.ZerosBytes[:])
		t.MessagesHash = tH[:]
	} else {
		tHash := generateMessageHash(t.Messages)
		t.MessagesHash = tHash[:]
	}

	return nil
}

func generateMessageHash(messages []TransactionMessage) [32]byte {
	i := 0
	var tHash [32]byte
	for i < len(messages) {
		if i == 0 {
			tHash = sha256.Sum256(messages[i].Key[:])

		} else {
			tHash = common.AddAndHash(tHash[:], messages[i].Key[:])
		}
		tHash = common.AddAndHash(tHash[:], messages[i].Value[:])
		// don't include signatures past originator
		i = i + 1
	}
	return tHash
}

func (t *Transaction) SetTransactionID() error {
	tHash := GenerateTransactionID(t)
	t.TransactionID = tHash[:]

	return nil
}

func GenerateTransactionID(t *Transaction) [32]byte {
	var byte8 [8]byte
	var tHash [32]byte
	copy(byte8[:], []byte(strconv.FormatInt(t.Timestamp, 10)))
	tHash = sha256.Sum256(byte8[:])
	tHash = common.AddAndHash(byte8[:], t.MessagesHash[:])
	tHash = common.AddAndHash(tHash[:], t.OutputsHash[:])
	tHash = common.AddAndHash(tHash[:], t.InputsHash[:])

	return tHash
}

func (t *Transaction) SignTransaction(privateKey []byte) error {
fmt.Println("SIGN TRANSACTIONS")
	var addr Address
	var signed bool
	signed = false
	addr.LoadBytesPrivate(privateKey)
	i := 0

	if len(t.TransactionID) == 0 {
		return errors.New("Can't sign empty transaction id")
	}

	// is it already signed?
	if len(t.Signatures) != 0 {
		fmt.Println("Already Signed")
		for i < len(t.Signatures) {
			fmt.Println("Checking Signature:", i)

			if reflect.DeepEqual(t.Signatures[i].SignatureAddress, addr.PublicBytes) {
				fmt.Println("input and transaction address match:", i)
				//signed = ed.VerifyCanonical(&addr.PublicBytes, t.TransactionID, &t.Signatures[i].SignatureBytes)
				//epub := ed25519.PublicKey(t.Signatures[i].SignatureAddress)
				epub := ed25519.PublicKey(t.Signatures[i].SignatureAddress[:])
				signed = ed25519.Verify(epub ,t.TransactionID,t.Signatures[i].SignatureBytes[:])
			}
			i = i + 1
		}
	}
	fmt.Println("HERE")

	if !signed {

		var ts TransactionSignature
		// sign with 64 bytes

		priv := ed25519.NewKeyFromSeed(privateKey)
		fmt.Println("priv")
		fmt.Println(priv)
		
		sig, err := priv.Sign(rand.Reader, t.TransactionID,crypto.Hash(0))
	
		if err != nil {
			fmt.Println("Signing Error",err)
		}

		copy(ts.SignatureBytes[0:64], sig[:])
		fmt.Println("")
		fmt.Println("Transaction Signature")
		fmt.Println("key")
		//fmt.Println(hex.EncodeToString(pa[:]))
		fmt.Println("data")
		fmt.Println(hex.EncodeToString(t.TransactionID))
		fmt.Println("Signature")
		fmt.Println(hex.EncodeToString(sig[:]))
		epub := ed25519.PublicKey(addr.PublicBytes[:])
		signed = ed25519.Verify(epub ,t.TransactionID,ts.SignatureBytes[:])
	
		//signed = ed.VerifyCanonical(&addr.PublicBytes, t.TransactionID, &ts.SignatureBytes)
		fmt.Println("SignedTransaction:", signed)
		fmt.Println(ts)

		ts.SignatureAddress= addr.PublicBytes
		t.AddSignature(ts)
	}
fmt.Println("Signed")
fmt.Println(signed)
	return nil
}

func (t *Transaction) ValidateTransaction(NodeURL string) error {
	// check balances

	amt, err := t.checkTransactionAmounts(NodeURL)
	fmt.Println("TBE:", err, ":", amt)

	if amt < 0 {

		return errors.New("Invalid Transaction Balance ")
	}
	if err != nil {
		return err
	}

	// check input and output amounts
	err = t.checkTransactionSignatures()
	if err != nil {
		fmt.Println(err)
		return err
	}
	// check hashes
	err = t.checkTransactionHashes()
	return nil
}

func RequestTransactionByHash(messageHash []byte, transactionBytes []byte) ([]byte, error) {
	return nil, nil
}

func (t *Transaction) checkTransactionAmounts(NodeURL string) (int64, error) {

	// we need to make sure input accounts have the balance to pay.
	// to handle possible multi input issues or gaming the addresses
	//  we need to keep a running total on the addresses.
	// a map works well

	addresslist := make(map[string]int64)

	tAmount := int64(0)
	testAmount := int64(0)
	var i int64

	i = 0

	fee := t.VerifyFee()

	if len(t.Inputs) == 0 {
		return 0, errors.New("No Inputs")
	}
	for i < int64(len(t.Inputs)) {
		pubr := BytesToReadablePublic(t.Inputs[i].Address[:])
		addresslist[pubr] = addresslist[pubr] + t.Inputs[i].Amount
		// as of today, the first input address pays the fee
		if i == 0 {
			addresslist[pubr] = addresslist[pubr] + fee
		}
		tAmount = tAmount + t.Inputs[i].Amount
		i = i + 1
	}

	// done consolidating inputs.
	// now see if the input addresses have the balance needed
	// a coinbase transaction is out of balance by definition.
	//    there are no inputs

	for addressstring, amt := range addresslist {
		testAmount = GetBalance(NodeURL,addressstring)
		if amt > testAmount {
			return 0, errors.New(addressstring + " has " + fmt.Sprint(testAmount) + ", but needs " + fmt.Sprint(amt) + " SCX")
		}
	}

	if len(t.Outputs) == 0 {
		return 0, errors.New("No Outputs")
	}
	i = 0
	for i < int64(len(t.Outputs)) {
		tAmount = tAmount - t.Outputs[i].Amount
		i = i + 1
	}

	//fee gets burned, so inputs should equal outputs plus fee
	// mostly.  since the fee was estimated before the bytes for the fee were added, this is fuzzy.
	//Not really, but this is a TODO as we just need to get the varint lengths for the fee input
	tAmount = tAmount - fee
	fmt.Println("tAmount:", tAmount)

	if tAmount < -1 || tAmount > 10 {
		return tAmount, errors.New("Inputs should equal Outputs + fee")
	}

	return tAmount, nil

}

func GetTransactionByHash(NodeURL string,transactionHash string) (Transaction, error) {
	fmt.Println("GetTransaction")
	fmt.Println(NodeURL)
	var tReq TransactionRequest
	tReq.TransactionHash = transactionHash
	tBytes, err := json.Marshal(tReq)
	var trans Transaction

	resp, err := http.Post(NodeURL+"/transaction", "application/json", bytes.NewBuffer([]byte(tBytes)))
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal(body, &trans)

	if err != nil {
		fmt.Println(err)
		return trans, err
	}

	err = json.Unmarshal(body, &trans)

	return trans, err

}

func GetTransactionsByAddress(NodeURL string,publicAddress string) ([]Transaction, error) {
	fmt.Println("GetTransactionsByAddress")
	fmt.Println(NodeURL)
	var tReq TransactionRequest
	tReq.PublicAddress = publicAddress
	tBytes, err := json.Marshal(tReq)
	var trans []Transaction

	resp, err := http.Post(NodeURL+"/transaction", "application/json", bytes.NewBuffer([]byte(tBytes)))
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal(body, &trans)

	if err != nil {
		fmt.Println(err)
		return trans, err
	}

	err = json.Unmarshal(body, &trans)

	return trans, err

}

func GetPendingTransactions(NodeURL string,publicAddress string) ([]Transaction, error) {

	var trans []Transaction

	resp, err := http.Post(NodeURL+"/pendingtransactions", "application/json", nil)
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal(body, &trans)

	if err != nil {
		fmt.Println(err)
		return trans, err
	}

	err = json.Unmarshal(body, &trans)

	return trans, err

}

func (t *Transaction) checkTransactionSignatures() error {

	var i int
	var b32 [32]byte


	var requiredSignatures int64
	var requiredSigned int64
	var totalSignatures int64
	var inputSignatures int64
	var sgn bool

	i = 0

	// input signatures
	fmt.Println("t.Inputs")
	fmt.Println(t.Inputs)
	for i < len(t.Inputs) {

	//	copy(b64[0:], t.Inputs[i].SignatureBytes[:])
		sigData, err := t.Inputs[i].BytesToSign()
		if err != nil {
			fmt.Println("input sig error on check signatures:", err)
		}
		// a positive amount required an Input Signature
		if t.Inputs[i].Amount > 0 {
			requiredSignatures = requiredSignatures + 1
		}
		epub := ed25519.PublicKey(t.Inputs[i].Address[:])
		sgn = ed25519.Verify(epub ,sigData[:],t.Inputs[i].SignatureBytes[:])

		//sgn = ed.VerifyCanonical(epub, sigData[:], &b64)
		// if th einput is signed, check to see if the address also signed transaction
		fmt.Println("sgn##############:", sgn)
		if sgn {
			fmt.Println(t.Inputs[i].Amount)
			if t.Inputs[i].Amount > 0 {
				fmt.Println("amt>0")
				inputSignatures = inputSignatures + 1
				// did the address that signed this input also sign the transaction?
				for _, ts := range t.Signatures {
					if reflect.DeepEqual(ts.SignatureAddress, t.Inputs[i].Address) {
						//found this address in the transaction signatures.
						// verify the signature
						copy(b32[0:], ts.SignatureAddress[:])
						fmt.Println("Verify transaction signatures")
						epub := ed25519.PublicKey(ts.SignatureAddress[:])
						tCheck := ed25519.Verify(epub ,t.TransactionID,ts.SignatureBytes[:])
		fmt.Println("tCheck")
		fmt.Println(tCheck)
						//tCheck := ed.VerifyCanonical(epub, t.TransactionID, &ts.SignatureBytes)
						fmt.Println("Signature Check in Verify inputs:", tCheck)
						if tCheck {
							requiredSigned = requiredSigned + 1
						}
					}
				}
			}
			totalSignatures = totalSignatures + 1
		}
		i = i + 1
	}
	// if required signatures is greater than signed, sigs missing
	fmt.Println(requiredSignatures, ":", requiredSigned)
	if requiredSignatures > requiredSigned {
		return errors.New("Required Signtures Missing.")
	}
	// since you have all the required signatures, do you have
	// the total number of signatures required.
	// 3 of 5, that sort of thing.

	if len(t.Signatures) < int(t.RequiredSignatures) {
		return errors.New("Need More Signatures for Multisig.")
	}

	return nil
}

func (t *Transaction) checkTransactionHashes() error {

	//verify input hashs
	inputHash := generateInputHash(t.Inputs)
	// verify output hashes
	outputHash := generateOutputHash(t.Outputs)
	// verify message hashes
	messageHash := generateMessageHash(t.Messages)
	// verify transactionid
	transactionid := GenerateTransactionID(t)

	if !reflect.DeepEqual(inputHash[:], t.InputsHash[:]) {
		return errors.New("Invalid Inputs Hash")
	}
	if !reflect.DeepEqual(outputHash[:], t.OutputsHash[:]) {
		return errors.New("Invalid Outputs Hash")
	}
	if !reflect.DeepEqual(messageHash[:], t.MessagesHash[:]) {
		return errors.New("Invalid Messages Hash")
	}
	if !reflect.DeepEqual(transactionid[:], t.TransactionID[:]) {
		return errors.New("Invalid Transaction ID")
	}

	return nil
}

func (t *Transaction) PrintTransaction() {

	fmt.Println("TransactionID:", hex.EncodeToString(t.TransactionID)) //transactionhid (hash)
	fmt.Println("Inputs:")
	var adstr string
	for _, i := range t.Inputs {
		adstr = BytesToReadablePublic(i.Address[:])
		fmt.Println("Address:   ", adstr)                               //transactionhid (hash)
		fmt.Println("Amount:   ", i.Amount)                             //transactionhid (hash)
		fmt.Println("Time:   ", i.Timestamp)                            //transactionhid (hash)
		fmt.Println("Sig:   ", hex.EncodeToString(i.SignatureBytes[:])) //transactionhid (hash)

	}
	fmt.Println("InputHash:", hex.EncodeToString(t.InputsHash))
	fmt.Println("Outputs:")
	for _, o := range t.Outputs {
		adstr = BytesToReadablePublic(o.Address[:])
		fmt.Println("Address:   ", adstr)   //transactionhid (hash)
		fmt.Println("Amount:   ", o.Amount) //transactionhid (hash)
	}
	fmt.Println("OutputHash:", hex.EncodeToString(t.OutputsHash))

	fmt.Println("Messages:")
	for _, m := range t.Messages {
		fmt.Println("Key:   ", hex.EncodeToString(m.Key))       //transactionhid (hash)
		fmt.Println("Message:   ", hex.EncodeToString(m.Value)) //transactionhid (hash)
	}
	fmt.Println("MessageHash:", hex.EncodeToString(t.MessagesHash))
	fmt.Println("Timestamp:", t.Timestamp)

	fmt.Println("Signatures:")
	for _, s := range t.Signatures {
		fmt.Println("Address:   ", hex.EncodeToString(s.SignatureAddress[:])) //transactionhid (hash)
		fmt.Println("Signature:   ", hex.EncodeToString(s.SignatureBytes[:])) //transactionhid (hash)
	}
	fmt.Println("Required Signatures:", t.RequiredSignatures)

}

func BuildTransaction(NodeURL string,from Address, to Address, messagekey string, messagevalue string, amount int64) ([]byte, error) {

	var tran Transaction
	var inp TransactionInput
	var outp TransactionOutput
	var msg TransactionMessage

	// add input
	inp.Amount = amount
	inp.Address = from.PublicBytes
	inp.Timestamp = common.UnixMilli()
	err := tran.AddSignedInput(from.PrivateBytes[:], inp)
	if err != nil {
		fmt.Println(err)
	}

	//add output
	outp.Address = to.PublicBytes
	outp.Amount = amount
	err = tran.AddOutput(outp)
	if err != nil {
		fmt.Println(err)
	}

	//add messages
	msg.Key = []byte(messagekey)
	msg.Value = []byte(messagevalue)
	err = tran.AddMessage(msg)
	if err != nil {
		fmt.Println(err)
	}

	//add fee
	var feeAmount = tran.CalculateFee()
	var feeInp TransactionInput
	feeInp.Address = from.PublicBytes
	feeInp.Amount = int64(feeAmount)
	feeInp.Timestamp = common.UnixMilli()
	err = tran.AddSignedInput(from.PrivateBytes[:], feeInp)
	if err != nil {
		fmt.Println(err)
	}
	tran.Timestamp = common.UnixMilli()
	// add hashes
	err = tran.HashInputs()
	if err != nil {
		fmt.Println(err)
	}

	err = tran.HashOutputs()
	if err != nil {
		fmt.Println(err)
	}

	err = tran.HashMessages()
	if err != nil {
		fmt.Println(err)
	}

	err = tran.SetTransactionID()
	if err != nil {
		fmt.Println(err)
	}

	err = tran.SignTransaction(from.PrivateBytes[:])
	if err != nil {
		fmt.Println("Sign Transaction Error")
		fmt.Println(err)
	}
	fmt.Println(tran.ValidateTransaction(NodeURL))
	tran.PrintTransaction()

	resp, err := SendNewTransaction(NodeURL,tran)
	fmt.Println(resp, err)
	return tran.TransactionID, err
}

func SendNewTransaction(NodeURL string,transaction Transaction) (TransactionResponse, error) {
	fmt.Println("SendNewTransaction:")
	fmt.Println(NodeURL)
	jsn, err := json.Marshal(transaction)
	resp, err := http.Post(NodeURL + "/newtransaction", "application/json", bytes.NewBuffer([]byte(jsn)))
	if err != nil {
		fmt.Println(err)
		fmt.Println("Error Hitting URL ")
	}
	var nbResp TransactionResponse

	//defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Can't get TransactionHash")
	}

	fmt.Println(string(body))

	err = json.Unmarshal(body, &nbResp)
	if nbResp.Status == "Accepted" {
		// network can be equal or +1 and by 'synced'
		return nbResp, nil
	} else {
		return nbResp, err
	}

}
