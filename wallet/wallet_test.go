package wallet_test

import (
	"encoding/hex"
	"fmt"
	"github.com/configwizard/sdk/wallet"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestWalletGenerateNew(t *testing.T) {
	w, err := wallet.GenerateNewWallet("/tmp/wallets.rawContent.go")
	assert.Nil(t, err, "error not nil")
	assert.NotNil(t, w.Accounts[0], "no account")
	assert.NotEqualf(t, "", w.Accounts[0].Address, "no address")
}

func TestWalletSecureGenerateNew(t *testing.T) {
	path := "/tmp/wallets.rawContent.go"
	password := "password"
	w, err := wallet.GenerateNewSecureWallet(path, "", password)
	fmt.Print(wallet.PrettyPrint(w))
	assert.Nil(t, err, "error not nil")
	assert.NotNil(t, w.Accounts[0], "no account")
	assert.NotEqualf(t, "", w.Accounts[0].Address, "no address")

	creds, err := wallet.GetCredentialsFromPath(path, w.Accounts[0].Address, password)
	assert.Nil(t, err, "error not nil")
	assert.NotEqual(t, nil, creds)
	creds, err = wallet.GetCredentialsFromWallet("", "password", w)
	assert.Nil(t, err, "error not nil")
	assert.NotEqual(t, nil, creds)
}

func TestGenerateWallet(t *testing.T) {
	w, _ := wallet.GenerateNewWallet("/tmp/wallets.rawContent.go")
	bytePublicKey := hex.EncodeToString(w.Accounts[0].PrivateKey().PublicKey().Bytes())
	fmt.Println("test key hex:", bytePublicKey)
}

func TestTransfer(t *testing.T) {
	//we need a test wallet to run this that has gas for this to work.
	//probably should not be run in automated testing.
	path := os.Getenv("TEST_WALLET_PATH")
	if path == "" {
		t.SkipNow()
	}
	password := "password"
	w, err := wallet.RetrieveWallet(path)
	if err != nil || len(w.Accounts) == 0 {
		t.Fatal(err)
	}
	err = w.Accounts[0].Decrypt(password, w.Scrypt)
	if err != nil {
		fmt.Println("could not decrypt wallet with password ", err)
		t.Fatal(err)
	}
	txId, validUntilBlock, err := wallet.TransferTokenWithPrivateKey(w.Accounts[0], wallet.RPC_WEBSOCKET, w.Accounts[0].Address, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("txId %s validUntil %d, err %s\r\n", txId.StringLE(), validUntilBlock, err)
}
