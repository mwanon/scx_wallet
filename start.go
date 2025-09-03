package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/mwanon/scx_node/apistructs"
	"github.com/mwanon/scx_node/common"
	"github.com/mwanon/scx_wallet/structs"
)



func main() {
	var NodeURL string
	var isProd bool

    if len(os.Args) == 1 {
		showUsage()
		os.Exit(0)
	}
	fmt.Println(os.Args[1] )
	if len(os.Args) == 2 {
		if os.Args[1] == "newaddress" {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Run this from the command line so it doesn't disappear.")
			fmt.Println("Running SCX Miner with no parameters will help you create a new key pair. ")
			fmt.Println("  you will want to write down the two addresses created.")
			fmt.Println("")
			fmt.Println("The address that starts with SCS is your secret key.  ")
			fmt.Println("This is the one you never want to lose.  It controls your tokens.")
			fmt.Println("If you lose it, your tokens are stuck forever.")
			fmt.Println("If someone else has it, they can control your tokens.")
			fmt.Println("")
			fmt.Println("The address that starts with SCS is your Public Address. ")
			fmt.Println("This is the one you share.")
			fmt.Println("If someone wants to send you SCX Tokens, they send to this address")
			fmt.Println("If you are going to look up your balance, this is the address you look for")
			fmt.Println("The public address has no control of your tokens, it just tells you ")
			fmt.Println("  how many tokens your private address.")
			fmt.Println("")
			fmt.Println("We need to use some random stuff to generate a keypair.")
			fmt.Println("Enter some random stuff (then hit enter):")

			seed, _ := reader.ReadString('\n')

			bseed := sha256.Sum256([]byte(seed))
			pkey := sha256.Sum256(bseed[:])
			//add a time interaction
			_ = binary.PutVarint(bseed[0:], common.UnixMilli())
			pkey = common.AddAndHash(pkey[:], bseed[:])

			fmt.Println("Once More (then hit enter):")
			seed, _ = reader.ReadString('\n')
			bseed = sha256.Sum256([]byte(seed))
			pkey = common.AddAndHash(pkey[:], bseed[:])
			//add a time interaction
			_ = binary.PutVarint(bseed[0:], common.UnixMilli())
			pkey = common.AddAndHash(pkey[:], bseed[:])

			var addr structs.Address
			addr.LoadBytesPrivate(pkey[:])
			fmt.Println("")
			fmt.Println("")
			fmt.Println("")
			fmt.Println("")
			fmt.Println("")
			fmt.Println("Your Addresses:")
			fmt.Println("")
			fmt.Println(addr.PrivateReadable)
			fmt.Println(addr.PublicReadable)
			fmt.Println("")
			fmt.Println("")
			fmt.Println("Remember to save these.")
			fmt.Println("Write them down, print them, whatever.")
			fmt.Println("")
			return
		}
	}

	isProd = true
	var fromAddress structs.Address
	var toAddress structs.Address
	amount := int64(0)
	var messagekey string
	var messagevalue string
	var command string
	var commandvalue string
	var err error
	//var NodeURL string
	i := 1
	for i < len(os.Args) {

		if os.Args[i] == "-from" || os.Args[i] == "-f" {
			i = i + 1
			err = fromAddress.LoadPrivateAddress(os.Args[i])
			if err != nil {
				fmt.Println("Not a valid private address.  It is the one that starts with SCS. ")
				fmt.Println("It is the address you are sending FROM. ")
				fmt.Println("If it still complains, you might have a typo.")
				return
			}
		}

		if os.Args[i] == "-to" || os.Args[i] == "-t" {
			i = i + 1
			err = toAddress.LoadPublicAddress(os.Args[i])
			if err != nil {
				fmt.Println("Not a valid public address.  It is the one that starts with SCX. ")
				fmt.Println("It is the address you are sending TO. ")
				fmt.Println("If it still complains, you might have a typo.")
				return
			}
		}
		if os.Args[i] == "-messagekey" || os.Args[i] == "-mk" {
			i = i + 1
			messagekey = os.Args[i]
		}

		if os.Args[i] == "-messagevalue" || os.Args[i] == "-mv" {
			i = i + 1
			messagevalue = os.Args[i]
		}

		if os.Args[i] == "-amount" || os.Args[i] == "-a" {
			i = i + 1
			amount, err = strconv.ParseInt(os.Args[i], 10, 64)
			if err != nil {
				fmt.Println("Amount should be a integer.  No Decimals.  1 SCX token = 10000 (to 4 decimal places)")
				return
			}
			if amount < 0 {
				fmt.Println("Amount should be a positive integer.  No Negative Numbers.")
				return
			}
		}

		if os.Args[i] == "-node" || os.Args[i] == "-n" {
			i = i + 1
			NodeURL = os.Args[i]
		}

		if os.Args[i] == "-balance" || os.Args[i] == "-b" {
			i = i + 1
			command = "balance"
			err = toAddress.LoadPublicAddress(os.Args[i])
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		if os.Args[i] == "-transaction" || os.Args[i] == "-b" {
			i = i + 1
			command = "transaction"
			commandvalue = os.Args[i]
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		if os.Args[i] == "-faucet" {
			i = i + 1
			command = "faucet"
			commandvalue = os.Args[i]
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		if os.Args[i] == "-test" {
			isProd = false
		}
		if os.Args[i] == "-prod" {
			isProd = true
		}

		i = i + 1
	} // finished reading commandline arguments
	fmt.Println("COMMAND:", command)
	if command == "faucet" {
		var tResp structs.TransactionResponse
		tResp = HitFaucet(commandvalue)
		fmt.Println(tResp)

		return
	}

	if isProd {

		NodeURL = NodeURL + ":18777"
	} else {
		NodeURL = NodeURL + ":17777"
	}

	heightCheck := GetBlockHeights(NodeURL)

	if heightCheck.BlockHeight < 1 {
		fmt.Println("BlockHeight = 0.  Are you looking at the correct SCX Node?")
		fmt.Println("                  Did you set -test or -prod ?")
		return
	}

	if heightCheck.BlockHeight < heightCheck.NetworkHeight-2 {
		fmt.Println("Your Node Block Height is less than the network.")
		fmt.Println("Please wait for your node to sync with the network.")
		return
	}

	if command == "balance" {
		bal := GetBalance(NodeURL,toAddress.PublicReadable)
		fmt.Println(toAddress.PublicReadable)
		fmt.Println(bal/10000.0, " SCX")
		return
	}

	if command == "transaction" {
		tran, err := GetTransaction(NodeURL,commandvalue)
		if err != nil {
			fmt.Println(err)
		} else {
			tran.PrintTransaction()
		}
		return
	}

	// if you are still here, you passed all of the cursory input checks for the transaction





	tranid, err := structs.BuildTransaction(NodeURL,fromAddress, toAddress, messagekey, messagevalue, amount)
	if err != nil {
		fmt.Println(err)

	} else {
		fmt.Println("The Transaction looks successful")

		fmt.Println("To see if it is pending, run ")
		fmt.Println("")
		fmt.Println("SCX miner pending")
		fmt.Println("")
		fmt.Println("and look for transaction:")
		fmt.Println(hex.EncodeToString(tranid))
		fmt.Println("")
		fmt.Println("")
		fmt.Println("If you do not see it, it may have posted already.")
		fmt.Println("")

	}
}

func GetBalance(NodeURL string,publicaddress string) int64 {
	var bReq apistructs.BalanceRequest
	bReq.PublicAddress = publicaddress
	rBytes, err := json.Marshal(bReq)

	resp, err := http.Post(NodeURL+"/balance", "application/json", bytes.NewBuffer([]byte(rBytes)))
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

//Hitfaucet only works on testnet...if it is up.
func HitFaucet(publicaddress string) structs.TransactionResponse {
	var bReq apistructs.BalanceRequest
	var tResp structs.TransactionResponse
	bReq.PublicAddress = publicaddress

	rBytes, err := json.Marshal(bReq)

	resp, err := http.Post("http://testnet.rvmrecycling.com:17777/faucet", "application/json", bytes.NewBuffer([]byte(rBytes)))
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal(body, &tResp)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(tResp)
	}
	return tResp

}

func GetTransaction(NodeURL string, publicaddress string) (structs.Transaction, error) {
	var bReq apistructs.TransactionRequest
	var response []structs.Transaction
	bReq.TransactionHash = publicaddress
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

	err = json.Unmarshal(body, &response)

	return response[0], err

}

func GetBlockHeights(NodeURL string) apistructs.HeightResponse {
	var bhResp apistructs.HeightResponse
	resp, err := http.PostForm(NodeURL+"/blockheight", nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Can't get block height")
	}

	err = json.Unmarshal(body, &bhResp)
	return bhResp
	// when peer network is up, use network height
	//	if bhResp.BlockHeight+2 > bhResp.NetworkHeight {
	// network can be equal or +1 and by 'synced'
	////		return bhResp.NetworkHeight
	//	} else {
	//		return -1
	//	}
}

func showUsage() {
	fmt.Println("Usage:")
	fmt.Println("-from or -f  then address that starts with SCS")
	fmt.Println("-to or -t  target address that starts with SCX")
	fmt.Println("-amount or -a  amount as whole number.  1.0 SCX token = 10000")
	fmt.Println("-node or -n  full http address (without port or trailing '/') of SCX Node you want to use")
	fmt.Println("-messagekey or -mk  a label for the message you wish to attach (optional)")
	fmt.Println("-messagevalue or -mv  the message content (optional)")
	fmt.Println("")
	fmt.Println("-balance <address>")

	fmt.Println("-test or -prod   ")
	fmt.Println("   ")
	fmt.Println("-newaddress as only parameter will generate a new address with a few prompts.")
	fmt.Println("   ")
	fmt.Println("-faucet  only works with -test.  Hits SCX testnet main node faucet server.  ")

}
