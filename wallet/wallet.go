package wallet

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/configwizard/sdk/utils"
	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/pkg/core/block"
	"github.com/nspcc-dev/neo-go/pkg/core/native/nativehashes"
	"github.com/nspcc-dev/neo-go/pkg/core/state"
	"github.com/nspcc-dev/neo-go/pkg/core/transaction"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/encoding/address"
	"github.com/nspcc-dev/neo-go/pkg/encoding/fixedn"
	"github.com/nspcc-dev/neo-go/pkg/neorpc"
	"github.com/nspcc-dev/neo-go/pkg/neorpc/result"
	client "github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/actor"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/gas"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/nep17"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/notary"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/waiter"
	"github.com/nspcc-dev/neo-go/pkg/smartcontract/trigger"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/vm/opcode"
	"github.com/nspcc-dev/neo-go/pkg/vm/vmstate"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"log"
	"math/big"
	"strings"
	"time"
)

const testNetExplorerUrl = "https://dora.coz.io/transaction/neo3/testnet"
const mainnetExplorerUrl = "https://dora.coz.io/transaction/neo3/mainnet"

type RPC_NETWORK string

// const (
// todo - this should move to config object
const RPC_TEST_WEBSOCKET RPC_NETWORK = "wss://rpc.t5.n3.nspcc.ru:20331/ws" //testnet or mainnet??
const RPC_MAIN_WEBSOCKET RPC_NETWORK = "wss://rpc10.n3.nspcc.ru:10331/ws"

//	RPC_TESTNET RPC_NETWORK = "https://rpc.t5.n3.nspcc.ru:20331/"
//	RPC_MAINNET RPC_NETWORK = "https://rpc.t5.n3.nspcc.ru:20331/"
//
// )
func NewAccountFromPublicKey(key ecdsa.PublicKey) *wallet.Account {
	return notary.FakeSimpleAccount((*keys.PublicKey)(&key))
}
func GenerateNewWallet(path string) (*wallet.Wallet, error) {
	acc, err := wallet.NewAccount()
	if err != nil {
		return &wallet.Wallet{}, err
	}
	w, err := wallet.NewWallet(path)
	w.AddAccount(acc)
	return w, err
}

func GenerateEphemeralAccount() (*wallet.Account, error) {
	acc, err := wallet.NewAccount()
	if err != nil {
		return nil, err
	}
	return acc, nil
}
func GenerateNewSecureWallet(path, name, password string) (*wallet.Wallet, error) {
	w, err := wallet.NewWallet(path)
	w.CreateAccount(name, password)
	return w, err
}

func RetrieveWallet(path string) (*wallet.Wallet, error) {
	w, err := wallet.NewWalletFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("can't read the wallets: %walletPath", err)
	}
	return w, nil
}
func GetCredentialsFromWallet(address, password string, w *wallet.Wallet) (ecdsa.PrivateKey, error) {
	return getKeyFromWallet(w, address, password)
}
func GetCredentialsFromPath(path, address, password string) (ecdsa.PrivateKey, error) {
	w, err := wallet.NewWalletFromFile(path)
	if err != nil {
		return ecdsa.PrivateKey{}, fmt.Errorf("can't read the wallets: %walletPath", err)
	}

	return getKeyFromWallet(w, address, password)
}
func GetWalletFromPrivateKey(key ecdsa.PrivateKey) *wallet.Account {
	privKey := keys.PrivateKey{PrivateKey: key}
	return wallet.NewAccountFromPrivateKey(&privKey)
}
func UnlockWallet(path, address, password string) (*wallet.Account, error) {
	w, err := wallet.NewWalletFromFile(path)
	if err != nil {
		return nil, err
	}
	var addr util.Uint160
	if len(address) == 0 {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(address)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}

	acc := w.GetAccount(addr)
	err = acc.Decrypt(password, w.Scrypt)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

type Nep17Token struct {
	Asset        util.Uint160 `json:"asset"`
	Amount       uint64       `json:"amount"`
	PrettyAmount string       `json:"pretty_amount"`
	Precision    int          `json:"precision"`
	Symbol       string       `json:"symbol"`
}

func QuickClient(ctx context.Context, websocket string) (*client.WSClient, error) {
	wsC, err := client.NewWS(ctx, string(websocket), client.WSOptions{ //fixme - create one client for all. (not strictly necessary but we don't necessarily want to leave SubmitTransaction open forever)
		Options:                        client.Options{},
		CloseNotificationChannelIfFull: false,
	})
	if err != nil {
		return nil, err
	}
	if err := wsC.Init(); err != nil {
		return nil, err
	}
	return wsC, nil
}
func ListenToBlocks(ctx context.Context, wsC *client.WSClient, blockChannel chan *block.Block) {
	_, err := wsC.ReceiveBlocks(nil, blockChannel)
	if err != nil {
		log.Fatalf("could not listen for blocks %s\n", err)
	}
	for {
		select {
		case b := <-blockChannel:
			fmt.Printf("block received %+v", b)
		}
	}
	select {
	case <-ctx.Done():
		fmt.Println("Context cancelled, stopping wallet listener")
		close(blockChannel)
	}
}
func ListenForWalletGasChanges(ctx context.Context, wsC *client.WSClient, address string, received chan nep17.TransferEvent) {
	notificationChannel := make(chan *state.ContainedNotificationEvent)

	defer close(notificationChannel)

	filter := &neorpc.NotificationFilter{Contract: &nativehashes.GasToken}
	resp, err := wsC.ReceiveExecutionNotifications(filter, notificationChannel)
	if err != nil {
		log.Fatalf("Failed to subscribe to notifications: %v", err)
	}

	fmt.Println("resp ", resp)
	// Listen for notifications
	go func() {
		for notification := range notificationChannel {
			fmt.Printf("Notification received: %+v\n", notification)
			var te nep17.TransferEvent
			err = te.FromStackItem(notification.Item)
			from := Uint160ToString(te.From)
			to := Uint160ToString(te.To)
			if from == address || to == address {
				fmt.Printf("transfer event from %s - to %s- %+v\n", from, to, te)
				received <- te
			}
		}
	}()

	// Keep the goroutine alive to listen to notifications
	select {
	case <-ctx.Done():
		fmt.Println("Context cancelled, stopping wallet listener")
		return
	}
}
func WaitForTransaction(ctx context.Context, wsC *client.WSClient, txHash string) error {
	version, err := wsC.GetVersion()
	blockCount, err := wsC.GetBlockCount()
	if err != nil {
		return err
	}

	txHash = strings.TrimPrefix(txHash, "0x")
	fmt.Println("length of tx hash ", len(txHash), txHash)
	txId, err := util.Uint256DecodeStringLE(txHash)
	if err != nil {
		fmt.Println("txiderr ", err)
		return err
	}

	newWaiter := waiter.New(wsC, version)
	// Use Waiter to wait for the transaction
	aer, err := newWaiter.Wait(txId, blockCount+100, nil)
	if err != nil {
		fmt.Println("waiter error ", err)
		return err
	}

	if aer.VMState != vmstate.Halt { // HALT is successful
		return err
	}
	fmt.Printf("Transaction confirmed successfully %+v\r\n", aer)
	return nil
}

// decrypted account
// fixme if we know the public key and not the recipient string....
func CreateWCTransaction(acc *wallet.Account /* RPC_WEBSOCKET */, websocket string, recipient string, amount float64) (*transaction.Transaction, util.Uint256, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	wsC, err := client.NewWS(ctx, string(websocket), client.WSOptions{ //fixme - create one client for all. (not strictly necessary but we don't necessarily want to leave SubmitTransaction open forever)
		Options:                        client.Options{},
		CloseNotificationChannelIfFull: false,
	})
	if err != nil {
		return nil, util.Uint256{}, err
	}
	err = wsC.Init()
	if err != nil {
		return nil, util.Uint256{}, err
	}
	act, err := actor.NewSimple(wsC, acc)
	if err != nil {
		return nil, util.Uint256{}, err
	}
	gasAct := gas.New(act)
	recipientHash, err := address.StringToUint160(recipient)
	if err != nil {
		return nil, util.Uint256{}, err
	}
	decimals, err := gasAct.Decimals()
	if err != nil {
		return nil, util.Uint256{}, err
	}
	gasPrecisionAmount, err := ConvertToBigInt(amount, decimals)
	if err != nil {
		return nil, util.Uint256{}, err
	}
	unsignedTransaction, err := gasAct.TransferUnsigned(acc.ScriptHash(), recipientHash, gasPrecisionAmount, nil)
	if err != nil {
		return nil, util.Uint256{}, err
	}
	fmt.Println("HASH WHEN CRAFTING TRANSACTION ", unsignedTransaction.Hash())
	signedData := make([]byte, 4+util.Uint256Size)
	binary.LittleEndian.PutUint32(signedData, uint32(act.GetNetwork()))
	h := unsignedTransaction.Hash()
	copy(signedData[4:], h[:])
	return unsignedTransaction, h, nil
}
func SubmitWCTransaction(dw *wallet.Account, websocket string, transactionData, signedData []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	wsC, err := client.NewWS(ctx, string(websocket), client.WSOptions{
		Options:                        client.Options{},
		CloseNotificationChannelIfFull: false,
	})
	if err != nil {
		fmt.Println("no ws client ", err)
		return "", err
	}
	err = wsC.Init()
	if err != nil {
		return "", err
	}

	signingTransaction, err := transaction.NewTransactionFromBytes(transactionData)
	if err != nil {
		fmt.Println("could not create transaction from bytes ", err)
		return "", err
	}
	fmt.Println("HASH WHEN REBUILDING TRANSACTION ", signingTransaction.Hash())
	//invoc := append([]byte{byte(opcode.PUSHDATA1), keys.SignatureLen}, signedData...)
	fmt.Println("length of signedData = ", len(signedData), signedData, string(signedData))
	if len(signingTransaction.Scripts) != 1 {
		return "", errors.New("no scripts to attach invocation to")
	}
	signingTransaction.Scripts[0].InvocationScript = append([]byte{byte(opcode.PUSHDATA1), keys.SignatureLen}, signedData...)
	fmt.Printf("invocation set")
	marsalled, err := signingTransaction.MarshalJSON()
	if err != nil {
		return "", err
	}
	fmt.Printf("signed transaction %+v\r\n", string(marsalled))
	txId, err := wsC.SendRawTransaction(signingTransaction)
	if err != nil {
		fmt.Println("send raw transaction error", err)
		return "", err
	}
	version, err := wsC.GetVersion()
	if err != nil {
		fmt.Println("get version error ", err)
		return "", err
	}
	aer, err := waiter.New(wsC, version).Wait(txId, signingTransaction.ValidUntilBlock, nil)
	if err != nil {
		fmt.Println("waiter error ", err)
		return "", err
	}
	if aer.VMState != vmstate.Halt { //HALT is successful
		fmt.Println("error transaction - ", aer.FaultException)
		return "", errors.New(utils.ErrorTransacting + " " + aer.FaultException)
	}
	return txId.StringLE(), nil
}

func GetNep17Balances(ctx context.Context, acc string, rpcEndpoint string) ([]Nep17Token, error) {
	//ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	//defer cancel()
	cli, err := client.New(ctx, rpcEndpoint, client.Options{})
	if err != nil {
		return nil, err
	}
	addressUint160, err := StringToUint160(acc)
	if err != nil {
		return nil, err
	}
	balances, err := cli.GetNEP17Balances(addressUint160)
	if err != nil {
		return nil, err
	}
	var tokens []Nep17Token
	for _, balance := range balances.Balances {
		amount, ok := new(big.Int).SetString(balance.Amount, 10)
		if !ok {
			// Handle conversion error
			continue
		}
		tokens = append(tokens, Nep17Token{
			Asset:        balance.Asset,
			Amount:       amount.Uint64(),
			PrettyAmount: fixedn.ToString(amount, balance.Decimals),
			Precision:    balance.Decimals,
			Symbol:       balance.Symbol,
		})
	}
	return tokens, nil
}

func TransferTokenWithPrivateKey(acc *wallet.Account, websocket string, recipient string, amount float64) (util.Uint256, uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	wsC, err := client.NewWS(ctx, string(websocket), client.WSOptions{ //fixme - create one client for all. (not strictly necessary but we don't necessarily want to leave SubmitTransaction open forever)
		Options:                        client.Options{},
		CloseNotificationChannelIfFull: false,
	})
	if err != nil {
		return util.Uint256{}, 0, err
	}
	err = wsC.Init()
	if err != nil {
		return util.Uint256{}, 0, err
	}
	act, err := actor.NewSimple(wsC, acc)
	if err != nil {
		return util.Uint256{}, 0, err
	}
	gasAct := gas.New(act)
	recipientHash, err := address.StringToUint160(recipient)
	if err != nil {
		return util.Uint256{}, 0, err
	}
	decimals, err := gasAct.Decimals()
	if err != nil {
		return util.Uint256{}, 0, err
	}
	gasPrecisionAmount, err := ConvertToBigInt(amount, decimals)
	if err != nil {
		return util.Uint256{}, 0, err
	}
	version, err := wsC.GetVersion()
	if err != nil {
		return util.Uint256{}, 0, err
	}
	tx, validUntilBlock, err := gasAct.Transfer(act.Sender(), recipientHash, gasPrecisionAmount, nil)
	stateResponse, err := waiter.New(wsC, version).Wait(tx, validUntilBlock, err)
	if err != nil {
		fmt.Println("waiter error ", err)
		return util.Uint256{}, 0, err
	}
	if stateResponse.VMState != vmstate.Halt { //HALT is successful
		fmt.Println("error transaction - ", stateResponse.FaultException)
		return util.Uint256{}, 0, errors.New(utils.ErrorTransacting + " " + stateResponse.FaultException)
	}

	fmt.Printf("events %s %+v\r\n", tx, stateResponse.Events)
	fmt.Printf("stack %s %+v\r\n", tx, stateResponse.Stack)
	fmt.Printf("fault %s exception %+v\r\n", tx, stateResponse.FaultException)
	fmt.Printf("vm state %s %+v\r\n", tx, stateResponse.VMState)
	fmt.Println("transaction ID", tx.StringLE())
	return tx /*.StringLE()*/, 0, nil

}
func GenerateMultiSignWalletFromSigners() {
	//	https://github.com/nspcc-dev/neo-go/blob/fdf80dbdc56d5f634908a5f0eb5ada2d9c7565af/docs/notary.md
	//useful read https://github.com/nspcc-dev/neo-go/blob/d5e11e0a75403fc56f48f23c13d25597a5d5f5a5/pkg/wallet/account_test.go#L91
	//https://medium.com/neoresearch/understanding-multisig-on-neo-df9c9c1403b1
	//https://github.com/nspcc-dev/neo-go/blob/d5e11e0a75403fc56f48f23c13d25597a5d5f5a5/pkg/wallet/account.go#L196-L197

	//example public keys
	//hexs := []string{
	//	//insert your key here
	//	"02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2",
	//	"02103a7f7dd016558597f7960d27c516a4394fd968b9e65155eb4b013e4040406e",
	//	"02a7bc55fe8684e0119768d104ba30795bdcc86619e864add26156723ed185cd62",
	//	"03d90c07df63e690ce77912e10ab51acc944b66860237b608c4f8f8309e71ee699",
	//}
	//make sure YOUR public key is the first one so you can pay for the transaction
}
func GetPeers(ntwk RPC_NETWORK) ([]result.Peer, error) {
	ctx := context.Background()
	// use endpoint addresses of public RPC nodes, e.g. from https://dora.coz.io/monitor
	cli, err := client.New(ctx, string(ntwk), client.Options{})
	if err != nil {
		return []result.Peer{}, err
	}

	err = cli.Init()
	peers, err := cli.GetPeers()
	return peers.Connected, err
}

func ConvertScriptHashToAddressString(scriptHash string) (util.Uint160, string, error) {
	//contractScriptHash := "185ec84c2694684f1dbd2852c27f004d969653d5"
	scriptHash = strings.TrimPrefix(scriptHash, "0x")
	contractAddress, err := util.Uint160DecodeStringLE(scriptHash)
	if err != nil {
		return util.Uint160{}, "", fmt.Errorf("can't convert script hash %w\n", err)
	}
	return contractAddress, Uint160ToString(contractAddress), nil

}

func GetLogForTransaction(network RPC_NETWORK, transactionID util.Uint256) (*result.ApplicationLog, error) {
	ctx := context.Background()
	// use endpoint addresses of public RPC nodes, e.g. from https://dora.coz.io/monitor
	cli, err := client.New(ctx, string(network), client.Options{})
	if err != nil {
		return &result.ApplicationLog{}, fmt.Errorf("can't create client %w\n", err)
	}
	err = cli.Init()
	trig := trigger.All
	log, err := cli.GetApplicationLog(transactionID, &trig)
	return log, err
}

// getKeyFromWallet fetches private key from neo-go wallets structure
func getKeyFromWallet(w *wallet.Wallet, addrStr, password string) (ecdsa.PrivateKey, error) {
	var (
		addr util.Uint160
		err  error
	)

	if addrStr == "" {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(addrStr)
		if err != nil {
			return ecdsa.PrivateKey{}, fmt.Errorf("invalid wallets address %s: %w", addrStr, err)
		}
	}

	acc := w.GetAccount(addr)
	if acc == nil {
		return ecdsa.PrivateKey{}, fmt.Errorf("invalid wallets address %s: %w", addrStr, err)
	}

	if err := acc.Decrypt(password, keys.NEP2ScryptParams()); err != nil {
		return ecdsa.PrivateKey{}, errors.New("[decrypt] invalid password - " + err.Error())

	}

	return acc.PrivateKey().PrivateKey, nil
}
