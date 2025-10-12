package tokens

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/getCassette-io/sdk/payload"
	"github.com/getCassette-io/sdk/utils"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofscrypto "github.com/nspcc-dev/neofs-sdk-go/crypto"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

const (
	TypePrivateTokenManager string = "private_token_manager"
	TypeWCTokenManager             = "wc_token_manager"
	TypeMockTokenManager           = "mock_token_manager"
)

type Token interface {
	InvalidAt(epoch uint64) bool
	Sign(issuerAddress string, p payload.Payload) error
	GetSignature() payload.Signature
	SetSignature(signature payload.Signature)
	SignedData() []byte
}

type PrivateContainerSessionToken struct {
	Signature    payload.Signature
	SessionToken *session.Container
	Wallet       *wallet.Account
}

func (m *PrivateContainerSessionToken) SetSignature(s payload.Signature) {
	m.Signature = s
}
func (m PrivateContainerSessionToken) GetSignature() payload.Signature {
	return m.Signature
}
func (m PrivateContainerSessionToken) InvalidAt(epoch uint64) bool {
	return false
}
func (m PrivateContainerSessionToken) Sign(issuerAddress string, signedPayload payload.Payload) error {
	if m.SessionToken == nil {
		return errors.New(utils.ErrorNoToken)
	}
	if signedPayload.Signature == nil {
		return errors.New(utils.ErrorNoSignature)
	}
	bPubKey, err := hex.DecodeString(signedPayload.Signature.HexPublicKey)
	if err != nil {
		return err
	}
	var pubKey neofsecdsa.PublicKeyWalletConnect
	if err := pubKey.Decode(bPubKey); err != nil {
		return err
	}
	bSig, err := hex.DecodeString(signedPayload.Signature.HexSignature)
	if err != nil {
		fmt.Println("error decoding hex signature", err)
		return err
	}
	salt, err := hex.DecodeString(signedPayload.Signature.HexSalt)
	if err != nil {
		fmt.Println("error decoding hex salt", err)
		return err
	}

	// Use NewSignature and AttachSignature instead of NewStaticSigner for neofs-sdk-go rc15
	signature := neofscrypto.NewSignature(neofscrypto.ECDSA_DETERMINISTIC_SHA256, &pubKey, append(bSig, salt...))
	m.SessionToken.AttachSignature(signature)
	if !m.SessionToken.VerifySignature() {
		return errors.New(utils.ErrorNoSignature)
	}
	return nil
}
func (m PrivateContainerSessionToken) SignedData() []byte {
	return m.SessionToken.SignedData()
}

type PrivateBearerToken struct {
	Signature   payload.Signature
	BearerToken *bearer.Token
	Wallet      *wallet.Account
}

func (m *PrivateBearerToken) SetSignature(s payload.Signature) {
	m.Signature = s
}
func (m PrivateBearerToken) GetSignature() payload.Signature {
	return m.Signature
}
func (m PrivateBearerToken) InvalidAt(epoch uint64) bool {
	return false
}

/*
	func (m Manager) TemporarySignBearerTokenWithPrivateKey(bt *bearer.Token) error {
		var k = m.wallet.Accounts[0].PrivateKey()
		var e neofsecdsa.Signer
		e = (neofsecdsa.Signer)(k.PrivateKey)
		return bt.Sign(e) //is this the owner who is giving access priveliges???
*/
func (m PrivateBearerToken) Sign(issuerAddress string, signedPayload payload.Payload) error {
	if m.BearerToken == nil {
		return errors.New(utils.ErrorNoToken)
	}
	if signedPayload.Signature == nil {
		return errors.New(utils.ErrorNoSignature)
	}
	bytesPublicKey, err := hex.DecodeString(signedPayload.Signature.HexPublicKey)
	if err != nil {
		return err
	}
	var pubKey neofsecdsa.PublicKey
	if err := pubKey.Decode(bytesPublicKey); err != nil {
		return err
	}

	signer := neofsecdsa.Signer(m.Wallet.PrivateKey().PrivateKey)
	usr := user.NewFromECDSAPublicKey(ecdsa.PublicKey(pubKey))
	if err := m.BearerToken.Sign(user.NewSigner(signer, usr)); err != nil {
		return err
	}
	if !m.BearerToken.VerifySignature() {
		fmt.Println("not signed")
		return errors.New(utils.ErrorNoSignature)
	}
	return nil
}

func (m PrivateBearerToken) SignedData() []byte {
	return m.BearerToken.SignedData()
}

type PrivateKeyTokenManager struct {
	BearerTokens  map[string]Token //Will be loaded from database if we want to keep sessions across closures.
	SessionTokens map[string]Token
	W             *wallet.Account
	HaveToken     bool
	mutex         sync.Mutex // Add a mutex to the struct
}

func (t PrivateKeyTokenManager) Type() string {
	return TypePrivateTokenManager
}

func NewPrivateKeyTokenManager(a *wallet.Account, persist bool) PrivateKeyTokenManager {
	return PrivateKeyTokenManager{W: a, BearerTokens: make(map[string]Token), SessionTokens: make(map[string]Token)}
}

func (t *PrivateKeyTokenManager) AddBearerToken(address string, cnrID string, b Token) {
	t.mutex.Lock()         // Lock the mutex before modifying the map
	defer t.mutex.Unlock() // Ensure the mutex is unlocked after modifying
	t.BearerTokens[fmt.Sprintf("%s.%s", address, cnrID)] = b
}
func (t *PrivateKeyTokenManager) AddSessionToken(address, cnrID string, b Token) {
	t.mutex.Lock()         // Lock the mutex before modifying the map
	defer t.mutex.Unlock() // Ensure the mutex is unlocked after modifying
	t.SessionTokens[fmt.Sprintf("%s.%s", address, cnrID)] = b
}

// FindBearerToken should see if we have a valid token to do the job. If not create a new one.
func (t PrivateKeyTokenManager) FindContainerSessionToken(address string, id cid.ID, epoch uint64) (Token, error) {
	if tok, ok := t.SessionTokens[fmt.Sprintf("%s.%s", address, id)]; ok && tok.InvalidAt(1) {
		tok, ok := tok.(*ContainerSessionToken)
		if !ok {
			return nil, errors.New("no session token")
		}
		if tok.InvalidAt(epoch) {
			return tok, errors.New(utils.ErrorNoToken)
		}
		return tok, nil
	}
	return nil, errors.New(utils.ErrorNoToken)
}

func (t PrivateKeyTokenManager) NewSessionToken(lIat, lNbf, lExp uint64, cnrID cid.ID, verb session.ContainerVerb, issuerKey keys.PublicKey) (Token, error) {
	sessionToken := new(session.Container)
	sessionToken.ForVerb(verb)
	sessionToken.AppliedTo(cnrID)
	sessionToken.SetID(uuid.New())
	ephemeralGateKey := t.W.PublicKey()
	sessionToken.SetAuthKey((*neofsecdsa.PublicKey)(ephemeralGateKey))
	sessionToken.SetIat(lIat)
	sessionToken.SetNbf(lNbf)
	sessionToken.SetExp(lExp)

	var issuer user.ID
	issuer = user.NewFromECDSAPublicKey(ecdsa.PublicKey(issuerKey))
	sessionToken.SetIssuer(issuer)
	return &PrivateContainerSessionToken{
		SessionToken: sessionToken,
		Wallet:       t.W,
	}, nil
}

func (t PrivateKeyTokenManager) PopulatePrivateBearerToken(bt bearer.Token) PrivateBearerToken {
	return PrivateBearerToken{BearerToken: &bt, Wallet: t.W}
}
func (t PrivateKeyTokenManager) NewBearerToken(table eacl.Table, lIat, lNbf, lExp uint64, temporaryKey *keys.PublicKey) (Token, error) {
	temporaryUser := user.NewFromECDSAPublicKey(*(*ecdsa.PublicKey)(temporaryKey))
	var bearerToken bearer.Token
	bearerToken.SetEACLTable(table)
	bearerToken.ForUser(temporaryUser) //temporarily give this key rights to the actions in the table.
	bearerToken.SetExp(lExp)
	bearerToken.SetIat(lIat)
	bearerToken.SetNbf(lNbf)
	return &PrivateBearerToken{Wallet: t.W, BearerToken: &bearerToken}, nil
}
func (t PrivateKeyTokenManager) FindBearerToken(address string, id cid.ID, epoch uint64, operation eacl.Operation) (Token, error) {

	if tok, ok := t.BearerTokens[fmt.Sprintf("%s.%s", address, id)]; !ok || tok.InvalidAt(1) {
		return nil, errors.New(utils.ErrorNoToken)
	} else {
		tok, ok := tok.(*PrivateBearerToken)
		if !ok {
			return nil, errors.New(utils.ErrorNoToken)
		}
		bearerToken := tok.BearerToken
		// we now need to check the rules the token needs to have
		if !bearerToken.AssertContainer(id) {
			return nil, errors.New(utils.ErrorNoToken)
		}
		if tok.InvalidAt(epoch) { //fix me unnecessary
			return tok, errors.New(utils.ErrorNoToken)
		}
		records := bearerToken.EACLTable().Records()
		for _, v := range records {
			if v.Operation() == operation && v.Action() == eacl.ActionAllow {
				return tok, nil
			}
		}
	}
	return nil, errors.New(utils.ErrorNoToken)
}

func (t PrivateKeyTokenManager) GateKey() wallet.Account {
	return *t.W
}

type ContainerSessionToken struct {
	SessionToken *session.Container
	Signature    payload.Signature
}

func (c *ContainerSessionToken) SetSignature(s payload.Signature) {
	c.Signature = s
}
func (m ContainerSessionToken) GetSignature() payload.Signature {
	return m.Signature
}
func (s ContainerSessionToken) InvalidAt(epoch uint64) bool {
	return !s.SessionToken.ValidAt(epoch)
}

func (s ContainerSessionToken) SignedData() []byte {
	return s.SessionToken.SignedData()
}

func (s ContainerSessionToken) Sign(issuerAddress string, p payload.Payload) error {
	if s.SessionToken == nil {
		return errors.New(utils.ErrorNoToken)
	}
	var issuer user.ID
	fmt.Printf("payload signature %+v\r\n", p.Signature)
	err := issuer.DecodeString(issuerAddress)
	if err != nil {
		return err
	}
	bPubKey, err := hex.DecodeString(p.Signature.HexPublicKey)
	if err != nil {
		return err
	}
	var pubKey neofsecdsa.PublicKeyWalletConnect
	if err := pubKey.Decode(bPubKey); err != nil {
		return err
	}
	if p.Signature == nil {
		return errors.New(utils.ErrorNoSignature)
	}
	bSig, err := hex.DecodeString(p.Signature.HexSignature)
	if err != nil {
		fmt.Println("error decoding hex signature", err)
		return err
	}
	salt, err := hex.DecodeString(p.Signature.HexSalt)
	if err != nil {
		fmt.Println("error decoding hex signature", err)
		return err
	}

	// Use NewSignature and AttachSignature instead of NewStaticSigner for neofs-sdk-go rc15
	signature := neofscrypto.NewSignature(neofscrypto.ECDSA_WALLETCONNECT, &pubKey, append(bSig, salt...))
	s.SessionToken.AttachSignature(signature)
	fmt.Println("container session token has been signed")
	if !s.SessionToken.VerifySignature() {
		fmt.Println("verifying signature failed for container session token")
		return errors.New(utils.ErrorNoSignature)
	}
	return nil
}

type BearerToken struct {
	Signature   payload.Signature
	BearerToken *bearer.Token
}

func (b *BearerToken) SetSignature(s payload.Signature) {
	b.Signature = s
}
func (m BearerToken) GetSignature() payload.Signature {
	return m.Signature
}
func (b BearerToken) Sign(issuerAddress string, p payload.Payload) error {
	if b.BearerToken == nil {
		return errors.New(utils.ErrorNoToken)
	}
	var issuer user.ID
	err := issuer.DecodeString(issuerAddress)
	if err != nil {
		return err
	}
	if p.Signature == nil {
		return errors.New(utils.ErrorNoSignature)
	}
	bSig, err := hex.DecodeString(p.Signature.HexSignature)
	if err != nil {
		fmt.Println("error decoding hex signature", err)
		return err
	}
	salt, err := hex.DecodeString(p.Signature.HexSalt)
	if err != nil {
		fmt.Println("error decoding hex signature", err)
		return err
	}

	bPubKey, err := hex.DecodeString(p.Signature.HexPublicKey)
	if err != nil {
		return err
	}
	var pubKey neofsecdsa.PublicKeyWalletConnect
	err = pubKey.Decode(bPubKey)
	if err != nil {
		return err
	}

	// Use NewSignature and AttachSignature instead of NewStaticSigner for neofs-sdk-go rc15
	signature := neofscrypto.NewSignature(neofscrypto.ECDSA_WALLETCONNECT, &pubKey, append(bSig, salt...))
	b.BearerToken.AttachSignature(signature)
	if !b.VerifySignature() {
		return errors.New(utils.ErrorNoSignature)
	}
	return nil
}

func (b BearerToken) VerifySignature() bool {
	return b.BearerToken.VerifySignature()
}
func (b BearerToken) InvalidAt(epoch uint64) bool {
	return !b.BearerToken.ValidAt(epoch)
}

func (b BearerToken) SignedData() []byte {
	return b.BearerToken.SignedData()
}

type MockTokenManager struct {
	BearerTokens  map[string]Token //Will be loaded from database if we want to keep sessions across closures.
	SessionTokens map[string]Token //fixme - can this all be one in memory token store or do they need to be seperated
	W             *wallet.Account
}

func (t MockTokenManager) Type() string {
	return TypeMockTokenManager
}

func NewMockTokenManager(a *wallet.Account, persist bool) MockTokenManager {
	return MockTokenManager{W: a, BearerTokens: make(map[string]Token), SessionTokens: make(map[string]Token)}
}

func (t MockTokenManager) GateKey() wallet.Account {
	return *t.W
}

func (t MockTokenManager) AddBearerToken(address, cnrID string, b Token) {
}

func (t MockTokenManager) FindBearerToken(address string, id cid.ID, epoch uint64, operation eacl.Operation) (Token, error) {
	var bearerToken bearer.Token
	return &BearerToken{BearerToken: &bearerToken}, nil
}
func (t MockTokenManager) NewBearerToken(table eacl.Table, lIat, lNbf, lExp uint64, temporaryKey *keys.PublicKey) (Token, error) {
	var bearerToken bearer.Token
	return &BearerToken{BearerToken: &bearerToken}, nil
}
func (t MockTokenManager) AddSessionToken(address, cnrID string, b Token) {
}
func (t MockTokenManager) FindContainerSessionToken(address string, id cid.ID, epoch uint64) (Token, error) {
	sessionToken := new(session.Container)
	return &ContainerSessionToken{
		SessionToken: sessionToken,
	}, nil
}
func (t MockTokenManager) NewSessionToken(lIat, lNbf, lExp uint64, cnrID cid.ID, verb session.ContainerVerb, issuerKey keys.PublicKey) (Token, error) {
	sessionToken := new(session.Container)
	return &ContainerSessionToken{
		SessionToken: sessionToken,
	}, nil
}

// WalletConnectTokenManager is responsible for keeping track of all valid sessions so not to need to resign every time
// for now just bearer tokens, for object actions, containers use sessions and will sign for each action
// listing containers does not need a token
type WalletConnectTokenManager struct {
	Persisted     bool             //use a fake/mock token for the time being that matches the mock emitter's signatures (todo - clean this up)Z
	BearerTokens  map[string]Token //Will be loaded from database if we want to keep sessions across closures.
	SessionTokens map[string]Token //fixme - can this all be one in memory token store or do they need to be seperated
	W             *wallet.Account
	mutex         sync.Mutex // Add a mutex to the struct

}

func (t WalletConnectTokenManager) Type() string {
	return TypeWCTokenManager
}

func NewWalletConnectTokenManager(a *wallet.Account, persist bool) WalletConnectTokenManager {
	return WalletConnectTokenManager{W: a, BearerTokens: make(map[string]Token), SessionTokens: make(map[string]Token), Persisted: persist}
}

func (t WalletConnectTokenManager) GateKey() wallet.Account {
	return *t.W
}

func (t *WalletConnectTokenManager) AddBearerToken(address, cnrID string, b Token) {
	t.mutex.Lock()         // Lock the mutex before modifying the map
	defer t.mutex.Unlock() // Ensure the mutex is unlocked after modifying
	t.BearerTokens[fmt.Sprintf("%s.%s", address, cnrID)] = b
}

// FindBearerToken should see if we have a valid token to do the job. If not create a new one.
func (t WalletConnectTokenManager) FindBearerToken(address string, id cid.ID, epoch uint64, operation eacl.Operation) (Token, error) {
	fmt.Println("looking for bearer for action ", operation, t.BearerTokens)
	if tok, ok := t.BearerTokens[fmt.Sprintf("%s.%s", address, id)]; ok {
		tok, ok := tok.(*BearerToken)
		if !ok {
			return nil, errors.New("no beaer token")
		}
		fmt.Println("and... its a bearer token. Lets go!")
		bearerToken := tok.BearerToken
		// we now need to check the rules the token needs to have
		if !bearerToken.AssertContainer(id) {
			return nil, errors.New(utils.ErrorNoToken)
		}
		//if tok.InvalidAt(epoch) {
		//	return tok, errors.New(utils.ErrorNoToken)
		//}
		return tok, nil
		records := bearerToken.EACLTable().Records()
		for _, v := range records {
			if v.Operation() == operation && v.Action() == eacl.ActionAllow {
				fmt.Println("returning/found action allow for operation ", v.Operation())
				return tok, nil
			}
		}
		return nil, errors.New(utils.ErrorNoToken)
	}
	return nil, errors.New(utils.ErrorNoToken)
}

// NewBearerToken - if we don't have a valid bearer token, we'll need to create a new one.
// fixme - this is incorrectly producing a token. Use tokens.BearerToken instead.
func (t WalletConnectTokenManager) NewBearerToken(table eacl.Table, lIat, lNbf, lExp uint64, temporaryKey *keys.PublicKey) (Token, error) {
	var bearerToken bearer.Token
	if t.Persisted { //hack so we don't need a completely different interaface
		if err := bearerToken.UnmarshalJSON(testToken); err != nil {
			log.Fatal("could not unmarshal bdata ", err)
			return nil, err
		}
	} else {
		temporaryUser := user.NewFromECDSAPublicKey(*(*ecdsa.PublicKey)(temporaryKey))
		bearerToken.SetEACLTable(table)
		bearerToken.ForUser(temporaryUser) //temporarily give this key rights to the actions in the table.
		bearerToken.SetExp(lExp)
		bearerToken.SetIat(lIat)
		bearerToken.SetNbf(lNbf)
	}
	return &BearerToken{BearerToken: &bearerToken}, nil
}

func (t *WalletConnectTokenManager) WrapToken(token bearer.Token) Token {
	return &BearerToken{BearerToken: &token}
}
func (t *WalletConnectTokenManager) AddSessionToken(address, cnrID string, b Token) {
	t.mutex.Lock()         // Lock the mutex before modifying the map
	defer t.mutex.Unlock() // Ensure the mutex is unlocked after modifying
	t.SessionTokens[fmt.Sprintf("%s.%s", address, cnrID)] = b
}

// FindBearerToken should see if we have a valid token to do the job. If not create a new one.
func (t WalletConnectTokenManager) FindContainerSessionToken(address string, id cid.ID, epoch uint64) (Token, error) {
	if tok, ok := t.SessionTokens[fmt.Sprintf("%s.%s", address, id)]; ok && tok.InvalidAt(1) {
		tok, ok := tok.(*ContainerSessionToken)
		if !ok {
			return nil, errors.New("no session token")
		}
		// we now need to check the rules the token needs to have
		//if !sessionToken.Ass.AssertContainer(id) {
		//	return BearerToken{}, errors.New(utils.ErrorNoToken)
		//}
		//we can check a verb if we like.
		if tok.InvalidAt(epoch) {
			return tok, errors.New(utils.ErrorNoToken)
		}
		return tok, nil
	}
	return nil, errors.New(utils.ErrorNoToken)
}

func (t WalletConnectTokenManager) NewSessionToken(lIat, lNbf, lExp uint64, cnrID cid.ID, verb session.ContainerVerb, issuerKey keys.PublicKey) (Token, error) {
	sessionToken := new(session.Container)
	sessionToken.ForVerb(verb)
	sessionToken.SetID(uuid.New())
	ephemeralGateKey := t.W.PublicKey()
	sessionToken.SetAuthKey((*neofsecdsa.PublicKey)(ephemeralGateKey))
	sessionToken.SetIat(lIat)
	sessionToken.SetNbf(lNbf)
	sessionToken.SetExp(lExp)
	if cnrID.String() != "" { //this could be dangerous. Too easy to create an open session delete token
		sessionToken.ApplyOnlyTo(cnrID)
	}

	var issuer user.ID
	fmt.Println("WC sessioin token from key ", t.W.PublicKey().String())
	issuer = user.NewFromECDSAPublicKey(ecdsa.PublicKey((issuerKey))) //todo - where does this key come from?
	sessionToken.SetIssuer(issuer)
	return &ContainerSessionToken{
		SessionToken: sessionToken,
	}, nil
}

//
//func (t *WalletConnectTokenManager) AddBearerTokenByOperation(address string, operation eacl.Operation, bt *bearer.Token) {
//	t.BearerTokens[fmt.Sprintf("%s.%d", address, operation)] = BearerToken{BearerToken: bt}
//}

// func GeneratePermissionsTable(cid cid.ID, toWhom eacl.Target) eacl.Table {
// 	table := eacl.Table{}

// 	headAllowRecord := eacl.NewRecord()
// 	headAllowRecord.SetOperation(eacl.OperationHead)
// 	headAllowRecord.SetAction(eacl.ActionAllow)
// 	headAllowRecord.SetTargets(toWhom)

// 	rangeAllowRecord := eacl.NewRecord()
// 	rangeAllowRecord.SetOperation(eacl.OperationRange)
// 	rangeAllowRecord.SetAction(eacl.ActionAllow)
// 	rangeAllowRecord.SetTargets(toWhom)

// 	searchAllowRecord := eacl.NewRecord()
// 	searchAllowRecord.SetOperation(eacl.OperationSearch)
// 	searchAllowRecord.SetAction(eacl.ActionAllow)
// 	searchAllowRecord.SetTargets(toWhom)

// 	getAllowRecord := eacl.NewRecord()
// 	getAllowRecord.SetOperation(eacl.OperationGet)
// 	getAllowRecord.SetAction(eacl.ActionAllow)
// 	getAllowRecord.SetTargets(toWhom)

// 	putAllowRecord := eacl.NewRecord()
// 	putAllowRecord.SetOperation(eacl.OperationPut)
// 	putAllowRecord.SetAction(eacl.ActionAllow)
// 	putAllowRecord.SetTargets(toWhom)

// 	deleteAllowRecord := eacl.NewRecord()
// 	deleteAllowRecord.SetOperation(eacl.OperationDelete)
// 	deleteAllowRecord.SetAction(eacl.ActionAllow)
// 	deleteAllowRecord.SetTargets(toWhom)

// 	table.SetCID(cid)
// 	table.AddRecord(getAllowRecord)
// 	table.AddRecord(headAllowRecord)
// 	table.AddRecord(putAllowRecord)
// 	table.AddRecord(deleteAllowRecord)
// 	//now handle all the records for other users
// 	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
// 		record := eacl.NewRecord()
// 		record.SetOperation(op)
// 		record.SetAction(eacl.ActionDeny)
// 		eacl.AddFormedTarget(record, eacl.RoleOthers)
// 		table.AddRecord(record)
// 	}
// 	return table
// }

func stringToBytes(byt string) []byte {
	var bData []byte
	bDataParts := strings.Split(byt, ",")
	// Convert each part to a byte and add it to the array
	for _, part := range bDataParts {
		num, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			fmt.Println("Error converting string to int:", err)
		}
		bData = append(bData, byte(num))
	}
	return bData
}

var testToken = []byte(`{"body": {
  "eaclTable": {
   "version": {
    "major": 2905618382,
    "minor": 331648027
   },
   "containerID": {
    "value": "boDh5L/39MqPFBNSjNJviXQ/o6+L3yEcukjxuO6KG+c="
   },
   "records": [
    {
     "operation": "GETRANGEHASH",
     "action": "ALLOW",
     "filters": [
      {
       "headerType": "OBJECT",
       "matchType": "STRING_EQUAL",
       "key": "$Object:containerID",
       "value": "FApVZAiovHf7DfxGWyxAnphhZhJxAG4hibf7Z9tXtuo1"
      },
      {
       "headerType": "OBJECT",
       "matchType": "STRING_NOT_EQUAL",
       "key": "$Object:ownerID",
       "value": "NNHvoeHRR9tTtZsGv4ppNmmJJRiJPqNBk8"
      }
     ],
     "targets": [
      {
       "role": "SYSTEM",
       "keys": [
        "AQID",
        "BAUG"
       ]
      },
      {
       "role": "SYSTEM",
       "keys": [
        "AQID",
        "BAUG"
       ]
      }
     ]
    },
    {
     "operation": "GETRANGEHASH",
     "action": "ALLOW",
     "filters": [
      {
       "headerType": "OBJECT",
       "matchType": "STRING_EQUAL",
       "key": "$Object:containerID",
       "value": "Eagxo77cWAik1frN3CooaFGeM61F11Bo1wCMN79CYssg"
      },
      {
       "headerType": "OBJECT",
       "matchType": "STRING_NOT_EQUAL",
       "key": "$Object:ownerID",
       "value": "NdsxHpNt9pdHAhXNcDR53dXHojcoMbrfjP"
      }
     ],
     "targets": [
      {
       "role": "SYSTEM",
       "keys": [
        "AQID",
        "BAUG"
       ]
      },
      {
       "role": "SYSTEM",
       "keys": [
        "AQID",
        "BAUG"
       ]
      }
     ]
    }
   ]
  },
  "ownerID": {
   "value": "NcZMpW8UAHStGguJ88dUbI/1hhhWxGoacw=="
  },
  "lifetime": {
   "exp": "3",
   "nbf": "2",
   "iat": "1"
  }
 },
 "signature": null
}`)
