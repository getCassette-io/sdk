package controller

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/configwizard/sdk/container"
	"github.com/configwizard/sdk/database"
	"github.com/configwizard/sdk/emitter"
	"github.com/configwizard/sdk/notification"
	"github.com/configwizard/sdk/object"
	"github.com/configwizard/sdk/payload"
	gspool "github.com/configwizard/sdk/pool"
	"github.com/configwizard/sdk/readwriter"
	"github.com/configwizard/sdk/tokens"
	"github.com/configwizard/sdk/utils"
	"github.com/configwizard/sdk/waitgroup"
	"github.com/configwizard/sdk/wallet"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/encoding/address"
	"github.com/nspcc-dev/neo-go/pkg/encoding/fixedn"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/actor"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/gas"
	"github.com/nspcc-dev/neo-go/pkg/rpcclient/nep17"
	"github.com/nspcc-dev/neo-go/pkg/util"
	neoWallet "github.com/nspcc-dev/neo-go/pkg/wallet"
	wal "github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"log"
	"math/big"
	"reflect"
	"strconv"
	"sync"
	"time"
)

// type ObjectActionType func(p payload.Parameters, signedPayload payload.Payload, token Token) (notification.NewNotification, error)
type ObjectActionType func(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error
type ContainerActionType func(wg *waitgroup.WG, ctx context.Context, p container.ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error

type MockWallet struct {
	wal.Account
	emitter          emitter.Emitter
	Ctx              context.Context `json:"-"`
	PublicKey        string          `json:"publicKey"`
	WalletAddress    string          `json:"walletAddress"`
	Network          string          `json:"network"`
	AccountType      string          `json:"account_type"`
	OriginalMessage  string
	HexPubKey        string
	HexSignature     string
	HexSalt          string
	HexSignedMessage string
}

func (w MockWallet) Address() string {
	return w.WalletAddress
}

func NewMockWallet() MockWallet {
	//these values are incorrect for this wallet address.
	return MockWallet{
		OriginalMessage: "Hello, world!",
		WalletAddress:   "NQtxsStXxvtRyz2B1yJXTXCeEoxsUJBkxW",
		PublicKey:       "031ad3c83a6b1cbab8e19df996405cb6e18151a14f7ecd76eb4f51901db1426f0b",
		HexPubKey:       "031ad3c83a6b1cbab8e19df996405cb6e18151a14f7ecd76eb4f51901db1426f0b",
		HexSignature:    "6eb490f17f30c3e85f032ff47247499efe5cb0ce94dab5e31647612e361053574c96d584d3c185fb8474207e8f649d856b4d60b573a195d5e67e621a2b4c7f87",
		HexSalt:         "3da1f339213180ed4c46a12b6bd57eb6",
		HexSignedMessage: "" +
			"010001f0" + // fixed scheme prefix
			"34" + // length of salted message in bytes: 2x16 bytes for hex salt + 20 bytes for base64-encoded hello world = 52 (0x34)
			"3364613166333339323133313830656434633436613132623662643537656236" + // hex-encoded salt
			"534756736247387349486476636d786b49513d3d" + // message to sign (base64-encoded hello world)
			"0000", // fixed scheme suffix,
	}
}
func (w MockWallet) Sign(p payload.Payload) error {
	//in this case the payload is the `token.Signed()` data. Sign it with the key.
	//currently the signed data is stored in the mock
	//var k = w.PrivateKey()
	//var e neofsecdsa.Signer
	//e = (neofsecdsa.Signer)(k.PrivateKey)
	//if tok, ok := token.(tokens.BearerToken); ok {
	//	if err := tok.BearerToken.Sign(e); err != nil {
	//		return err
	//	}
	//}

	//fixme - is this actually signed? Due to value vs reference, i wonder....
	return nil
}

func (w MockWallet) PublicKeyHexString() string {
	// retrieve the public key from the wallet
	return w.HexPubKey
}
func (w *MockWallet) SetEmitter(em emitter.Emitter) {
	w.emitter = em
}

type RawAccount struct {
	Ctx           context.Context `json:"-"`
	WalletAddress string          `json:"walletAddress"`
	PublicKey     string          `json:"publicKey"`
	Network       string          `json:"network"`
	AccountType   string          `json:"account_type"`
	*wal.Account
	emitter emitter.Emitter `json:"-"`
}

func NewRawWalletFromFile(filepath string) (RawAccount, error) {
	return RawAccount{
		Account: nil,
	}, nil
}
func NewRawAccount(a *wal.Account) (RawAccount, error) {
	return RawAccount{
		Account: a,
	}, nil
}
func (w *RawAccount) SetEmitter(em emitter.Emitter) {
	w.emitter = em
}
func (w RawAccount) Sign(p payload.Payload) error {
	var e = (neofsecdsa.SignerRFC6979)(w.Account.PrivateKey().PrivateKey)
	signed, err := e.Sign(p.OutgoingData)
	if err != nil {
		return err
	}
	if p.Signature == nil {
		p.Signature = &payload.Signature{}
	}
	p.Signature.HexSignature = hex.EncodeToString(signed)
	////p := w.PublicKey()
	//exampel := ecdsa.PublicKey(w.PublicKey())
	//pKeySgtring := hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), exampel.X, exampel.Y))
	p.Signature.HexPublicKey = w.PublicKey
	//p.OutgoingData = signed //fixme: total hack. This is not how this field should be used
	return w.emitter.Emit(w.Ctx, emitter.RequestSign, p)
}

func (w RawAccount) PublicKeyHexString() string {
	// retrieve the public key from the wallet
	return w.PublicKey //fixme - should come from wallet
}

func (w RawAccount) Address() string {
	return w.WalletAddress //fixme should come from wallet. Hardcoded now
}

type WCWallet struct {
	Ctx           context.Context `json:"-"`
	WalletAddress string          `json:"walletAddress"`
	PublicKey     string          `json:"publicKey"`
	Network       string          `json:"network"`
	AccountType   string          `json:"account_type"`
	emitter       emitter.Emitter `json:"-"`
}

func (w *WCWallet) SetEmitter(em emitter.Emitter) {
	w.emitter = em
}
func (w WCWallet) Address() string {
	return w.WalletAddress
}
func (w WCWallet) Sign(p payload.Payload) error {
	sEnc := base64.StdEncoding.EncodeToString(p.OutgoingData)

	fmt.Println("b64 encoded outgoing data ", sEnc)
	//p.OutgoingData
	fmt.Printf("requested to sign %+v with %+v\r\n", p, w.emitter)
	return w.emitter.Emit(w.Ctx, emitter.RequestSign, p)
}

func (w WCWallet) PublicKeyHexString() string {
	return w.PublicKey
}

type Account interface {
	Sign(p payload.Payload) error
	PublicKeyHexString() string
	Address() string
}

type TokenManager interface {
	AddBearerToken(address, cnrID string, b tokens.Token)
	AddSessionToken(address, cnrID string, b tokens.Token)
	NewBearerToken(table eacl.Table, lIat, lNbf, lExp uint64, temporaryKey *keys.PublicKey) (tokens.Token, error)
	NewSessionToken(lIat, lNbf, lExp uint64, cnrID cid.ID, verb session.ContainerVerb, gateKey keys.PublicKey) (tokens.Token, error)
	FindContainerSessionToken(address string, id cid.ID, epoch uint64) (tokens.Token, error)
	FindBearerToken(address string, id cid.ID, epoch uint64, operation eacl.Operation) (tokens.Token, error)
	GateKey() wal.Account
	Type() string
}

// Controller manages the frontend and backend/SDK interconnectivity
type Controller struct {
	selectedNetwork        utils.Network
	Pl                     *pool.Pool
	wg                     *sync.WaitGroup
	ctx                    context.Context
	cancelCtx              context.CancelFunc
	OperationHandler       map[string]Context
	DB                     database.Store
	logger                 *log.Logger
	wallet                 Account
	TokenManager           TokenManager
	GateKey                neoWallet.Account
	Signer                 emitter.Emitter
	Notifier               notification.Notifier
	ProgressHandlerManager *notification.ProgressHandlerManager
	pendingEvents          map[payload.UUID]payload.Payload     //holds any asynchronous information sent to frontend
	objectActionMap        map[payload.UUID]ObjectActionType    // Maps payload UID to corresponding action
	containerActionMap     map[payload.UUID]ContainerActionType // Maps payload UID to corresponding action
}

func NewCustomController(wg *sync.WaitGroup, ctx context.Context /*cancelFunc context.CancelFunc,*/, progressBarEmitter emitter.Emitter,
	network utils.Network,
	notifier notification.Notifier,
	db database.Store,
	logger *log.Logger) (Controller, error) {
	ephemeralAccount, err := wal.NewAccount()
	if err != nil {
		return Controller{}, err
	}
	tokenManager := tokens.NewPrivateKeyTokenManager(ephemeralAccount, true)
	gateKey := tokenManager.GateKey()
	pl, err := gspool.GetPool(ctx, gateKey.PrivateKey().PrivateKey, utils.RetrieveStoragePeers(network))
	if err != nil {
		fmt.Println("error getting pool ", err)
		log.Fatal(err)
	}
	c := Controller{
		selectedNetwork:        network,
		Pl:                     pl,
		wg:                     wg,
		ctx:                    ctx,
		OperationHandler:       make(map[string]Context),
		logger:                 logger,
		DB:                     db,
		TokenManager:           &tokenManager,
		GateKey:                gateKey,
		Notifier:               notifier,
		ProgressHandlerManager: notification.NewProgressHandlerManager(notification.DataProgressHandlerFactory, progressBarEmitter),
		pendingEvents:          make(map[payload.UUID]payload.Payload),
		objectActionMap:        make(map[payload.UUID]ObjectActionType),
		containerActionMap:     make(map[payload.UUID]ContainerActionType),
	}
	c.Notifier.ListenAndEmit() //this sends out notifications to the frontend.
	return c, nil
}
func NewMockController(wg *sync.WaitGroup, ctx context.Context /*cancelFunc context.CancelFunc,*/, progressBarEmitter emitter.Emitter,
	network utils.Network,
	notifier notification.Notifier,
	db database.Store,
	logger *log.Logger) (Controller, error) {
	ephemeralAccount, err := wal.NewAccount()
	if err != nil {
		return Controller{}, err
	}

	tokenManager := tokens.NewMockTokenManager(ephemeralAccount, true)
	gateKey := tokenManager.GateKey()
	fmt.Println("retrieving network pool, standby...")
	pl, err := gspool.GetPool(ctx, gateKey.PrivateKey().PrivateKey, utils.RetrieveStoragePeers(network))
	if err != nil {
		fmt.Println("error getting pool ", err)
		log.Fatal(err)
	}
	c := Controller{
		selectedNetwork:        network,
		Pl:                     pl,
		wg:                     wg,
		ctx:                    ctx,
		OperationHandler:       make(map[string]Context),
		logger:                 logger,
		DB:                     db,
		TokenManager:           tokenManager,
		GateKey:                gateKey,
		Notifier:               notifier, //fixme - the setting of the ctx is bad...
		ProgressHandlerManager: notification.NewProgressHandlerManager(notification.DataProgressHandlerFactory, progressBarEmitter),
		pendingEvents:          make(map[payload.UUID]payload.Payload),
		objectActionMap:        make(map[payload.UUID]ObjectActionType),
		containerActionMap:     make(map[payload.UUID]ContainerActionType),
	}
	c.Notifier.ListenAndEmit() //this sends out notifications to the emitter
	return c, nil
}

type Context struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
}

func (c *Controller) NewContext(id string) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	c.OperationHandler[id] = Context{
		Ctx:        ctx,
		CancelFunc: cancelCtx,
	}
}

//
//// renewContext resets the controllers context. For multiple down/uploads this needs to be specific to the task
//func (c *Controller) renewContext() {
//	//ctx, cancelFunc := context.WithCancel(context.Background())
//	//c.ctx = ctx
//	//c.cancelCtx = cancelFunc
//}
//func (c Controller) WG() *sync.WaitGroup {
//	//return c.wg
//	return nil
//}
//func (c Controller) Add(i int) {
//	//c.wg.Add(i)
//}
//func (c Controller) Done() {
//	//c.wg.Done()
//}
//func (c Controller) Wait() {
//	//c.wg.Wait()
//}

func (c *Controller) Account() Account {
	return c.wallet
}

func (c *Controller) Balances() ([]wallet.Nep17Token, error) {
	bPubKey, err := hex.DecodeString(c.wallet.PublicKeyHexString())
	if err != nil {
		log.Fatal("could not decode public key - ", err)
	}
	var pubKey neofsecdsa.PublicKeyRFC6979

	err = pubKey.Decode(bPubKey)
	if err != nil {
		return nil, err
	}
	blGet := client.PrmBalanceGet{}
	blGet.SetAccount(user.ResolveFromECDSAPublicKey(ecdsa.PublicKey(pubKey))) //id of the current connected account

	fmt.Println("waiting to retrieve result")
	neofsGasBalance, err := c.Pl.BalanceGet(context.Background(), blGet)
	if err != nil {
		return nil, err
	}
	rpcNodes := utils.RetrieveRPCNodes(c.selectedNetwork)
	var lastErr error
	for _, node := range rpcNodes {
		balances, err := wallet.GetNep17Balances(c.ctx, c.wallet.Address(), node)
		if err != nil {
			lastErr = err
			continue // Try the next node
		}

		amount, ok := new(big.Int).SetString(strconv.FormatInt(neofsGasBalance.Value(), 10), 10)
		if !ok {
			// Handle conversion error
			continue
		}
		// Process and return balances if successful
		neoFSBalance := wallet.Nep17Token{
			Asset:        util.Uint160{},                  // Use appropriate Asset ID for NeoFS if available
			Amount:       uint64(neofsGasBalance.Value()), // Consider precision adjustment
			Precision:    int(neofsGasBalance.Precision()),
			PrettyAmount: fixedn.ToString(amount, int(neofsGasBalance.Precision())),
			Symbol:       wallet.NEO_FS_GAS_BALANCE,
		}
		balances = append([]wallet.Nep17Token{neoFSBalance}, balances...)
		return balances, nil
	}

	// Return the last encountered error if all RPC nodes failed
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New(utils.ErrorNotFound)
}

// these kind of have to be used in harmony
func (c *Controller) SetAccount(a Account) {
	fmt.Println("setting account here to ", a, reflect.TypeOf(a))
	c.wallet = a
}
func (c *Controller) SetSigningEmitter(em emitter.Emitter) {
	c.Signer = em
	fmt.Println("type of wallet here is ", reflect.TypeOf(c.wallet))
	if wcWallet, ok := c.wallet.(WCWallet); ok {
		wcWallet.SetEmitter(em)
	} else if rawWallet, ok := c.wallet.(RawAccount); ok {
		rawWallet.SetEmitter(em)
	} else if mockWallet, ok := c.wallet.(MockWallet); ok {
		mockWallet.SetEmitter(em)
	} else {
		fmt.Println("no emitter set")
	}
}
func NewDefaultController(a Account) (Controller, error) {
	return Controller{
		//ctx:                    nil,
		//cancelCtx:              nil,
		DB:                     nil,
		wallet:                 a,
		TokenManager:           nil,
		Signer:                 nil,
		Notifier:               nil,
		ProgressHandlerManager: nil,
		objectActionMap:        make(map[payload.UUID]ObjectActionType),
		pendingEvents:          make(map[payload.UUID]payload.Payload),
	}, nil
}

func (m *Controller) Startup(ctx context.Context) {
	//m.ctx = ctx //todo = this usually comes from Wails. However we need the cancel context available
}

// domReady is called after the front-end dom has been loaded
func (m *Controller) DomReady(ctx context.Context) {
}

// LoadSession is responsible for taking input from the user and creating the wallet to manage the session.
func (c *Controller) LoadSession(wallet Account) { //todo - these fields may not be available immediately
	//somehow the user informs us of the wallet they want to load. We should adjust the wallet here accordingly.
	c.wallet = wallet
}

// RequestSign asks the wallet to begin the signing process. This assumes signing is asynchronous
func (c *Controller) SignRequest(p payload.Payload) error {

	if c.wallet == nil {
		return errors.New(utils.ErrorNoSession)
	}
	c.logger.Println("c.wallet SignRequest", c.wallet, " - ", utils.GetCallerFunctionName())
	if _, ok := c.pendingEvents[payload.UUID(p.Uid)]; ok {
		//exists. end
		return errors.New(utils.ErrorPendingInUse)
	}
	//if we have a signed request
	c.pendingEvents[payload.UUID(p.Uid)] = p
	return c.wallet.Sign(p)
}

// UpdateFromPrivateKey just passes the signed payload onwrds. Use when have private key
func (c *Controller) UpdateFromPrivateKey(signedPayload payload.Payload) error {
	c.logger.Println("c.wallet UpdateFromPrivateKey", c.wallet)
	if c.wallet == nil {
		return errors.New(utils.ErrorNoSession)
	}
	if p, ok := c.pendingEvents[payload.UUID(signedPayload.Uid)]; ok {
		updatedPayload := p // Dereference to get a copy of the payload
		updatedPayload.Complete = true
		updatedPayload.Signature = &payload.Signature{}
		updatedPayload.Signature.HexSignature = signedPayload.Signature.HexSignature
		updatedPayload.Signature.HexPublicKey = signedPayload.Signature.HexPublicKey
		// Update the map with the new struct
		c.pendingEvents[payload.UUID(signedPayload.Uid)] = updatedPayload
		// Notify through the channel
		c.logger.Println("updatedPayloadSignature ", updatedPayload.Signature.HexSignature)
		updatedPayload.ResponseCh <- true
		return nil
	}
	return errors.New(utils.ErrorNotFound)
}

// UpdateFromWalletConnect will be called when a signed payload is returned (use with WC)
func (c *Controller) UpdateFromWalletConnect(signedPayload payload.Payload) error {
	if c.wallet == nil {
		return errors.New(utils.ErrorNoSession)
	}
	if p, ok := c.pendingEvents[payload.UUID(signedPayload.Uid)]; ok {
		c.logger.Println("uid ", signedPayload.Uid)
		updatedPayload := p // Dereference to get a copy of the payload
		updatedPayload.Complete = true
		updatedPayload.OutgoingData = nil //we are done with this. No need to pass it around now
		//tidier way to do this?
		updatedPayload.Signature = &payload.Signature{ // if this is null, there is no signature to attach to the token
			HexSignature: signedPayload.Signature.HexSignature,
			HexSalt:      signedPayload.Signature.HexSalt,
			HexPublicKey: signedPayload.Signature.HexPublicKey,
			HexMessage:   signedPayload.Signature.HexMessage,
		}
		// Update the map with the new struct
		c.pendingEvents[payload.UUID(signedPayload.Uid)] = updatedPayload
		// Notify through the channel
		updatedPayload.ResponseCh <- true
		return nil
	}
	//it could be a wallet update message
	c.logger.Println("c.wallet UpdateFromWalletConnect", signedPayload)
	return errors.New(utils.ErrorNotFound)
}

func (c *Controller) PerformContainerAction(wg *waitgroup.WG, ctx context.Context, cancelCtx context.CancelFunc, p payload.Parameters, action ContainerActionType) error {
	fmt.Printf("performing container action  %T -- %s\r\n", action, utils.GetCallerFunctionName())
	defer cancelCtx()
	var actionChan = make(chan notification.NewNotification)
	// here we check whether we should run the action directly (for whatever reason)
	if c.wallet == nil {
		return errors.New(utils.ErrorNoSession)
	}
	wgMessage := "container_action_chan-" + p.ID() + "_" + utils.GetCurrentFunctionName()
	wg.Add(1, wgMessage)
	go func() { //todo - this is done in both action functions
		defer wg.Done(wgMessage)
		for { //listen forever
			select {
			case <-ctx.Done():
				c.logger.Println("3 closed action chan handler")
				return
			case not, ok := <-actionChan:
				if !ok {
					fmt.Println("action chan believed to be closed")
					return
				}
				c.logger.Println("success type, creating notification for database")
				if not.Type == notification.Success { //do this before sending the notification success
					if err := c.DB.Create(database.NotificationBucket, p.ID(), []byte{}); err != nil {
						c.Notifier.QueueNotification(c.Notifier.Notification(
							"failed to store in database",
							"error storing object reference in db "+err.Error(),
							notification.Error,
							notification.ActionNotification))
					}
					fmt.Println("WE RECEIVED [container] SUCCESS!")
					c.logger.Println("3 closing everything down")
					cancelCtx()
				}
				c.Notifier.QueueNotification(not)

			}
		}
	}()
	containerParameters, ok := p.(container.ContainerParameter)
	if !ok {
		return errors.New("parameters not valid")
	}
	fmt.Println("Type assertion:", reflect.TypeOf(containerParameters))
	fmt.Printf("action manager retrieved container parameters %+v\r\n", containerParameters)
	var cnrId cid.ID
	fmt.Println("decoding ", p.ID())

	if err := cnrId.DecodeString(p.ID()); err != nil || containerParameters.Verb == 0 { //unknown verb for container unnamed
		fmt.Println("verb is empty. We are going to just attempt the action directly.")
		//no container ID. lets try anyway
		if err := action(wg, ctx, containerParameters, actionChan, nil); err != nil {
			//handle the error with the UI (n)
			fmt.Println("error executing action ", err)

			return err
		}
		fmt.Println("waiting for action to complete...")
		wg.Wait()
		fmt.Println("finished waiting for action to complete...")
		return nil
	}

	if containerParameters.Session { //forcing the creation of new session token for containers every time?
		//if tok, err := c.TokenManager.FindContainerSessionToken(c.wallet.Address(), cnrId, p.Epoch()); err == nil {
		//	//we believe we have a token that can perform
		//	//the action should now be passed what it was going to be passed anyway, along with the token that it can use to make the request.
		//	//these actions will be responsible for notifying UI themselves (i.e progress bars etc)
		//	if t, ok := tok.(*tokens.ContainerSessionToken); !ok {
		//		return errors.New("no session token available")
		//	} else {
		//		fmt.Println("using container session toke ", t.SessionToken.ID())
		//	}
		//	fmt.Println("FOUND - session token ", tok)
		//	if err := action(wg, ctx, containerParameters, actionChan, tok); err != nil {
		//		//notification (interface) handler would handle any errors here. (c.notificationHandler interface type)
		//		return err
		//	}
		//	fmt.Println("waiting for action to complete...")
		//	wg.Wait()
		//	fmt.Println("finished waiting for action to complete...")
		//	return nil // this task has been triggered. No need to continue
		//}

		fmt.Println("just going to always force session token creation")
	} else {
		if tok, err := c.TokenManager.FindBearerToken(c.wallet.Address(), cnrId, p.Epoch(), eacl.OperationSearch); err == nil {
			var t tokens.Token
			var ok bool
			if t, ok = tok.(*tokens.BearerToken); !ok { //this needs to change with the manager type
				if t, ok = tok.(*tokens.PrivateBearerToken); !ok { //this needs to change with the manager type
					return errors.New("no bearer token available")
				}
			} else {
				if err := action(wg, ctx, containerParameters, actionChan, t); err != nil {
					//notification (interface) handler would handle any errors here. (c.notificationHandler interface type)
					return err
				}
				fmt.Println("waiting for action to complete...")
				wg.Wait()
				fmt.Println("finished waiting for action to complete...")

				return nil // this task has been triggered. No need to continue
			}
		}
	}

	var neoFSPayload payload.Payload
	neoFSPayload.Uid = payload.UUID(uuid.New().String())
	neoFSPayload.ResponseCh = make(chan bool)
	c.logger.Println("created responsechannel ", neoFSPayload.ResponseCh)
	// Store the action in the map
	c.containerActionMap[payload.UUID(neoFSPayload.Uid)] = action
	//keƒy := c.TokenManager.GateKey()
	//fixme we need to use tokens if they already exist but...
	iAt, exp, err := gspool.TokenExpiryValue(ctx, c.Pl, 100)

	//convert user's public key to create a session for them

	bPubKey, err := hex.DecodeString(c.wallet.PublicKeyHexString())
	if err != nil {
		log.Fatal("could not decode public key - ", err)
	}
	var pubKey neofsecdsa.PublicKeyRFC6979

	err = pubKey.Decode(bPubKey)
	if err != nil {
		return err
	}

	var token tokens.Token
	if containerParameters.Session {
		//fixme - can verb become an operation and we instead use p.Operation()?
		//cnrId is meangingless here no?
		token, err = c.TokenManager.NewSessionToken(iAt, iAt, exp, cnrId, containerParameters.Verb, keys.PublicKey(pubKey)) //mock this out for different wallet types
		if err != nil {
			return err
		}
	} else {
		nodes := utils.RetrieveStoragePeers(c.selectedNetwork)
		//todo - this all needs sorted
		//this can then probably move to the token manager now to create a new token.
		bt, err := object.ContainerBearerToken(p, nodes) // fixme - this won't suffice for containers.
		if err != nil {
			fmt.Println("failed to create bearer ", err)
			return err
		}
		switch c.TokenManager.Type() {
		case tokens.TypePrivateTokenManager:
			// Attempt to cast 'token' to '*tokens.PrivateContainerSessionToken'
			if tokManager, ok := c.TokenManager.(*tokens.PrivateKeyTokenManager); ok {
				privateBearerToken := tokManager.PopulatePrivateBearerToken(bt)
				token = &privateBearerToken
			} else {
				fmt.Println("weird error. Shouldn't be here, no token manager")
				panic("no token manager - odd error")
			}

		default:
			token = &tokens.BearerToken{BearerToken: &bt}
		}
	}
	neoFSPayload.OutgoingData = token.SignedData()

	//c.logger.Println("bearer token data to sign (bearerToken.SignedData()) ", neoFSPayload.OutgoingData)
	// Wait for the payload to be signed in a separate goroutine
	//fmt.Println("requesting action ", action, " for ", p.ID())
	containerActionWGMessage := "container_action_exec" + p.ID() + "_" + utils.GetCurrentFunctionName()
	wg.Add(1, containerActionWGMessage)
	go func() {
		defer func() {
			cancelCtx()
			wg.Done(containerActionWGMessage)
			c.logger.Println("3. perform action stopped")
		}()
		for {
			select {
			case <-ctx.Done():
				c.logger.Println("3. closed action handler")
				return
			case <-neoFSPayload.ResponseCh: //waiting for a signing
				//we just received a signed token payload. Lets recreate the associated token
				// Payload signed, perform the action
				//we now need to add the signed token to the map
				//success? add it to list.
				//fixme - we are signing every time here which will be causing wallet connect to ask for too many signatures
				var latestPayload payload.Payload
				if pendingPayload, exists := c.pendingEvents[payload.UUID(neoFSPayload.Uid)]; exists {
					latestPayload = pendingPayload
				} else {
					return
				}
				//fixme - are we signing the token multiple times here??
				if err := token.Sign(c.wallet.Address(), latestPayload); err != nil {
					c.logger.Println("1. container error signing token ", err, c.wallet.Address(), latestPayload)
					return
				}
				//all tokens need to do this somewhere, so can do here.
				token.SetSignature(*latestPayload.Signature)
				//attach the signature we received to the token. It may be used to create signers later.
				if containerParameters.Session {
					//todo - is it possible that by the time we add the token and sign it, we haven't
					//got a signed token available when we ask for one again?
					//i.e how do we know this is signed???
					c.TokenManager.AddSessionToken(c.wallet.Address(), cnrId.String(), token)
				} else {
					c.TokenManager.AddBearerToken(c.Account().Address(), cnrId.String(), token) //listing container contents is done with a bearer
				}
				if act, exists := c.containerActionMap[payload.UUID(latestPayload.Uid)]; exists {
					if err := act(wg, ctx, containerParameters, actionChan, token); err != nil {
						//handle the error with the UI (n)
						c.logger.Println("error executing action ", err)
						return
					}
					delete(c.containerActionMap, payload.UUID(neoFSPayload.Uid)) // Clean up
					//if err := token.Sign(c.wallet.Address(), latestPayload); err != nil {
					//	c.logger.Println("2. container error signing token ", err, c.wallet.Address(), latestPayload)
					//	return
					//}
					//token.SetSignature(*latestPayload.Signature)
					//var t any  // Declare 't' as an empty interface to hold the cast token
					//
					//switch c.TokenManager.Type() {
					//case tokens.TypePrivateTokenManager:
					//	// Attempt to cast 'token' to '*tokens.PrivateContainerSessionToken'
					//	if castToken, ok := token.(*tokens.PrivateContainerSessionToken); ok {
					//		t = castToken.SessionToken
					//	} else if castToken, ok := token.(*tokens.PrivateBearerToken); ok {
					//		t = castToken.BearerToken
					//	}
					//default:
					//	// Attempt to cast 'token' to '*tokens.ContainerSessionToken'
					//	if castToken, ok := token.(*tokens.ContainerSessionToken); ok {
					//		t = castToken.SessionToken
					//	}
					//}
					//// Now 't' holds the cast token, but you should check whether the casting was successful
					//if t != nil {
					//	// 't' is successfully cast, and you can proceed with using it
					//	fmt.Println("verifying that the session has been signed")
					//	if !t.VerifySignature() {
					//		fmt.Println("verifying signature failed for container session token")
					//		return
					//	}
					//	fmt.Println("token passed verification. Attemping container action.")
					//} else {
					//	fmt.Println("there was not available session token for the manager type")
					//	return
					//}

					//var typ any
					//if c.TokenManager.Type() == tokens.TypeWCTokenManager {
					//	typ = typ.(*tokens.ContainerSessionToken)
					//} else if c.TokenManager.Type() == tokens.TypeMockTokenManager {
					//	typ = typ.(*tokens.ContainerSessionToken)
					//} else if c.TokenManager.Type() == tokens.TypePrivateTokenManager {
					//	typ = typ.(*tokens.PrivateContainerSessionToken)
					//}
					////check for specifically session token signing
					//if t, ok := token.(*tokens.ContainerSessionToken); ok {
					//	fmt.Println("verifying that the session has been signed")
					//	if !t.SessionToken.VerifySignature() {
					//		fmt.Println("verifying signature failed for container session token")
					//		return
					//	}
					//	fmt.Println("token passed verification. Attemping container action.")
					//}
				}
			}
		}
	}()

	// Request signing of a session token.
	if err := c.SignRequest(neoFSPayload); err != nil {
		return err
	}
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("GROUPS - ", len(wg.Groups()), wg.Groups())
	}()
	wg.Wait()
	c.logger.Println("FINISH closed action ", action)
	fmt.Println("groups - ", wg.Groups())
	return nil
}

// PerformObjectAction is partnered with any 'event' that requires and action from the user and could take a while.
// It runs the action that is stored, related to the payload that has been sent to the frontend.
func (c *Controller) PerformObjectAction(wg *waitgroup.WG, ctx context.Context, cancelCtx context.CancelFunc, p payload.Parameters, action ObjectActionType) error {
	//fmt.Println("4. c.wallet PerformObjectAction", c.wallet)
	if c.wallet == nil {
		return errors.New(utils.ErrorNoSession)
	}
	var cnrId cid.ID
	err := cnrId.DecodeString(p.ParentID())
	if err != nil {
		return err
	}

	//c.logger.Println("4. perform action started")
	var actionChan = make(chan notification.NewNotification)
	wgMessage := "action_chan-" + p.Name() + "_" + utils.GetCurrentFunctionName()
	wg.Add(1, wgMessage)
	c.logger.Println("3.1 starting action chan handler")
	go func() {
		defer wg.Done(wgMessage)
		for { //listen forever
			select {
			case <-ctx.Done():
				c.logger.Println("3 closed action chan handler")
				return
			case not, ok := <-actionChan:
				if !ok {
					fmt.Println("action chan believed to be closed")
					return
				}
				c.logger.Println("success type, creating notification for database")
				if not.Type == notification.Success { //do this before sending the notification success
					if err := c.DB.Create(database.NotificationBucket, p.ID(), []byte{}); err != nil {
						c.Notifier.QueueNotification(c.Notifier.Notification(
							"failed to store in database",
							"error storing object reference in db "+err.Error(),
							notification.Error,
							notification.ActionNotification))
					}
					fmt.Println("WE RECEIVED [OBJECT] SUCCESS!")
					c.logger.Println("3 closing everything down")
					cancelCtx()
				}
				c.Notifier.QueueNotification(not)

			}
		}
	}()

	//fixme = don't think can use bearer token for containers. need to change this call so that gets correct token from manager.
	//at this point we need to find out if we have a bearer token that can handle this action for us
	//1. check if we have a token that will fulfil the operation for the request
	//to force this, just provide a token to the token manager that will be picked up here.
	if bearerToken, err := c.TokenManager.FindBearerToken(c.wallet.Address(), cnrId, p.Epoch(), p.Operation()); err == nil {
		//we believe we have a token that can perform
		//the action should now be passed what it was going to be passed anyway, along with the token that it can use to make the request.
		//these actions will be responsible for notifying UI themselves (i.e progress bars etc)
		var objectParameters object.ObjectParameter
		var ok bool
		//var objectWriteCloser io.WriteCloser
		if objectParameters, ok = p.(object.ObjectParameter); ok {
			if p.Operation() == eacl.OperationGet { //fixme: - move this like the put was moved.
				//if objectParameters, ok = p.(object.ObjectParameter); ok {
				_, objectReader, err := object.InitReader(ctx, objectParameters, bearerToken)
				if err != nil {
					return err
				}
				if ds, ok := objectParameters.ReadWriter.(*readwriter.DualStream); ok {
					ds.Reader = objectReader
				} else {
					return errors.New("not a dual stream")
				}
				//thought: you could use the destinationObject to update the UI before its downloaded with an emitter
				//destinationObject.PayloadSize() //use this with the progress bar
			}
			//else if p.Operation() == eacl.OperationPut {
			//	objectWriteCloser, err = object.InitWriter(ctx, &objectParameters, bearerToken)
			//	if err != nil {
			//		return err
			//	}
			//	if ds, ok := objectParameters.ReadWriter.(*readwriter.DualStream); ok {
			//		ds.Writer = objectWriteCloser
			//	} else {
			//		return errors.New("not a dual stream")
			//	}
			//}
		} else {
			fmt.Println("operation get, but no objectparameterss. Bailing out")
			return err
		}
		fmt.Printf("objectParameters Before %s - %+v\r\n", objectParameters.ActionOperation.String(), objectParameters)
		if err := action(wg, ctx, objectParameters, actionChan, bearerToken); err != nil {
			return err
		}
		return nil // this task has been triggered. No need to continue
	}
	var neoFSPayload payload.Payload
	neoFSPayload.Uid = payload.UUID(uuid.New().String())
	neoFSPayload.ResponseCh = make(chan bool)
	c.logger.Println("created responsechannel ", neoFSPayload.ResponseCh)
	// Store the action in the map
	c.objectActionMap[payload.UUID(neoFSPayload.Uid)] = action

	//key := c.TokenManager.GateKey()
	nodes := utils.RetrieveStoragePeers(c.selectedNetwork)
	//todo - this all needs sorted
	bt, err := object.ObjectBearerToken(cnrId, p, nodes) // fixme - this won't suffice for containers.
	//fixme - the expiries are not set
	//iAt, exp, err := gspool.TokenExpiryValue(ctx, c.Pl, 100)
	//if err != nil {
	//	return err
	//}
	bearerToken := &tokens.BearerToken{BearerToken: &bt}
	//bearerToken, err := c.TokenManager.NewBearerToken(bt.EACLTable(), iAt, iAt, exp, key.PublicKey()) //mock this out for different wallet types
	//if err != nil {
	//	return err
	//}

	////update the payload to the data to sign
	neoFSPayload.OutgoingData = bearerToken.SignedData()

	//c.logger.Println("bearer token data to sign (bearerToken.SignedData()) ", neoFSPayload.OutgoingData)
	// Wait for the payload to be signed in a separate goroutine
	wgMessage = "action_exec" + p.Name() + "_" + utils.GetCurrentFunctionName()
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			c.logger.Println("3. perform action stopped")
		}()
		for {
			select {
			case <-ctx.Done():
				c.logger.Println("3. closed action handler")
				return
			case <-neoFSPayload.ResponseCh: //waiting for a signing
				//we just received a signed token payload. Lets recreate the associated token
				// Payload signed, perform the action
				var latestPayload payload.Payload
				//c.logger.Printf("payload - ", neoFSPayload)
				if pendingPayload, exists := c.pendingEvents[neoFSPayload.Uid]; exists {
					latestPayload = pendingPayload
				} else {
					return
				}
				if act, exists := c.objectActionMap[latestPayload.Uid]; exists {
					if err := bearerToken.Sign(c.wallet.Address(), latestPayload); err != nil {
						c.logger.Println("error signing token ", err)
						return
					}
					//for certain actions objects need a 'pre-requisite'
					//we need to run this first. We can use the operation to check
					var objectParameters object.ObjectParameter
					var ok bool
					//var objectWriteCloser io.WriteCloser
					if objectParameters, ok = p.(object.ObjectParameter); ok {
						if p.Operation() == eacl.OperationGet {
							//if objectParameters, ok = p.(object.ObjectParameter); ok {
							_, objectReader, err := object.InitReader(ctx, objectParameters, bearerToken)
							if err != nil {
								return
							}
							if ds, ok := objectParameters.ReadWriter.(*readwriter.DualStream); ok {
								ds.Reader = objectReader
							} else {
								return
							}
							//thought: you could use the destinationObject to update the UI before its downloaded with an emitter
							//destinationObject.PayloadSize() //use this with the progress bar
						}
						//else if p.Operation() == eacl.OperationPut {
						//	//fixme - mutating the objectParameters here for the ID? Good idea?
						//	objectWriteCloser, err := object.InitWriter(ctx, &objectParameters, bearerToken)
						//	if err != nil {
						//		return
						//	}
						//	if ds, ok := objectParameters.ReadWriter.(*readwriter.DualStream); ok {
						//		ds.Writer = objectWriteCloser
						//	} else {
						//		return
						//	}
						//}
					} else {
						fmt.Println("operation get, but no objectparameterss. Bailing out")
						return
					}
					fmt.Printf("objectParameters Before %s - %+v\r\n", objectParameters.ActionOperation.String(), objectParameters)
					if err := act(wg, ctx, objectParameters, actionChan, bearerToken); err != nil {
						//handle the error with the UI (n)
						c.logger.Println("error executing action ", err)
						return
					}
					//else if p.Operation() == eacl.OperationPut {
					//	if payloadWriter, ok := objectWriteCloser.(*slicer.PayloadWriter); ok { //todo - this should really be moved to the object itself.
					//		fmt.Println("closing writer")
					//		if err := payloadWriter.Close(); err != nil {
					//			return
					//		}
					//		fmt.Println("writing ID to ", payloadWriter.ID().String(), "p.Id ", payloadWriter.ID())
					//	}
					//}
					delete(c.objectActionMap, neoFSPayload.Uid) // Clean up
				}
			}
		}
	}()

	// Request signing
	if err := c.SignRequest(neoFSPayload); err != nil {
		return err
	}
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("GROUPS - ", len(wg.Groups()), wg.Groups())
	}()
	wg.Wait()
	c.logger.Println("FINISH closed action ", action)
	fmt.Println("groups - ", wg.Groups())
	return nil
}

// fixme - this might want to return more information
func (c *Controller) NetworkInformation() string {
	return utils.RetrieveNetworkFileSystemAddress(c.selectedNetwork)
}

type privTmpEvent struct {
	TxId *string
	c    *Controller
}

func (t privTmpEvent) Emit(ctx context.Context, message emitter.EventMessage, pld any) error {
	if p, ok := pld.(payload.Payload); !ok {
		return errors.New("not a signable payload")
	} else {
		bSig, err := hex.DecodeString(p.Signature.HexSignature)
		if err != nil {
			fmt.Println("error decoding hex signature", err)
			return err
		}
		txId, err := t.c.ConcludeTransaction(p.MetaData, bSig)
		if err != nil {
			return err
		}
		t.TxId = &txId
	}

	return nil
}
func (c *Controller) PrivateTopUp(amount float64) error {
	//pld, err := c.InitGasTransfer(c.NetworkInformation(), amount)
	//if err != nil {
	//	return err
	//}
	//
	//var txId string
	//var tmpEmitter = privTmpEvent{
	//	&txId,
	//	c,
	//}
	if rawWallet, ok := c.wallet.(RawAccount); ok {
		//rawWallet.SetEmitter(tmpEmitter)
		//rawWallet.Sign(pld)
		//rawWallet.

		cli, err := rpcclient.New(context.Background(), utils.RetrieveRPCNodes(c.selectedNetwork)[0], rpcclient.Options{})
		if err != nil {
			fmt.Println("1 ", err)
			return err
		}
		fmt.Printf("rawWallet.Accoutn %+v\r\n", rawWallet.Account)
		a, err := actor.NewSimple(cli, rawWallet.Account)
		if err != nil {
			fmt.Println("2 ", err)
			return err
		}
		n17 := nep17.New(a, gas.Hash)

		tgtAcc, err := address.StringToUint160(c.NetworkInformation())
		if err != nil {
			fmt.Println("3 ", err)
			return err
		}
		txid, u, err := n17.Transfer(a.Sender(), tgtAcc, big.NewInt(int64(amount)), nil)
		if err != nil {
			fmt.Println("4 ", err)
			return err
		}
		stateResponse, err := a.Wait(txid, u, err)
		if err != nil {
			fmt.Println("5 ", err)
			return err
		}
		fmt.Printf("events %s %+v\r\n", txid, stateResponse.Events)
		fmt.Printf("stack %s %+v\r\n", txid, stateResponse.Stack)
		fmt.Printf("fault %s exception %+v\r\n", txid, stateResponse.FaultException)
		fmt.Printf("vm state %s %+v\r\n", txid, stateResponse.VMState)
		fmt.Println("transaction ID", txid.StringLE())
	}

	return nil
}

// InitGasTransfer crafts the transaction but does not sign it.  A wallet must now sign it and call ConcludeTranscation.
func (c *Controller) InitGasTransfer(recipientAddress string, amount float64) (payload.Payload, error) {
	bPubKey, err := hex.DecodeString(c.Account().PublicKeyHexString())
	if err != nil {
		return payload.Payload{}, fmt.Errorf("decode HEX public key from WalletConnect: %w", err)
	}

	var pubKey neofsecdsa.PublicKeyWalletConnect

	err = pubKey.Decode(bPubKey)
	if err != nil {
		return payload.Payload{}, fmt.Errorf("invalid/unsupported public key format from WalletConnect: %w", err)
	}

	fmt.Println("public key being used for transaction - ", c.Account().PublicKeyHexString())
	//fixme - the websocket should be part of the network data
	//fixme - why are we recreating the wallet here from public key when the controller has the wallet? test both.
	//however its this or cast the c.Account back to a wallet.Account...
	unsignedTransaction, _, err := wallet.CreateWCTransaction(wallet.NewAccountFromPublicKey((ecdsa.PublicKey)(pubKey)), wallet.RPC_WEBSOCKET, recipientAddress, amount)
	jsonTransaction, err := unsignedTransaction.MarshalJSON()
	if err != nil {
		return payload.Payload{}, err
	}
	p := payload.Payload{
		OutgoingData: jsonTransaction,             //sign this.
		MetaData:     unsignedTransaction.Bytes(), //use this to recraft the transaction when you have the signature
	}
	return p, err
}

func (c *Controller) ConcludeTransaction(transactionData, signedData []byte) (string, error) {
	//fixme - this should select the websocket url based on some parameter
	bPubKey, err := hex.DecodeString(c.Account().PublicKeyHexString())
	if err != nil {
		return "", fmt.Errorf("decode HEX public key from WalletConnect: %w", err)
	}
	fmt.Println("public key concluding transaction - ", c.Account().PublicKeyHexString())

	var pubKey neofsecdsa.PublicKeyWalletConnect

	err = pubKey.Decode(bPubKey)
	if err != nil {
		return "", fmt.Errorf("invalid/unsupported public key format from WalletConnect: %w", err)
	}

	txId, err := wallet.SubmitWCTransaction(wallet.NewAccountFromPublicKey((ecdsa.PublicKey)(pubKey)), wallet.RPC_WEBSOCKET, transactionData, signedData)
	if err != nil {
		return "", err
	}
	return txId, nil
}
