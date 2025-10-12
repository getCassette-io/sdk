package container

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/getCassette-io/sdk/database"
	"github.com/getCassette-io/sdk/emitter"
	"github.com/getCassette-io/sdk/notification"
	object2 "github.com/getCassette-io/sdk/object"
	"github.com/getCassette-io/sdk/tokens"
	"github.com/getCassette-io/sdk/utils"
	"github.com/getCassette-io/sdk/waitgroup"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
	"strconv"
	"strings"
	"time"
)

type ContainerAction interface {
	SynchronousContainerHead(ctx context.Context, cnrId cid.ID, pl *pool.Pool) (Container, error)
	Head(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error
	Restrict(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error
	Create(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error
	Read(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error
	List(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error
	Delete(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error
	SetNotifier(notifier notification.Notifier) // Assuming NotifierType is the type for Notifier
	SetStore(store database.Store)              // Assuming StoreType is the type for Store
}

const (
	attributeName      = "Name"
	attributeTimestamp = "Timestamp"
)

type ContainerParameter struct {
	Id               string
	Description      string
	PublicKey        ecdsa.PublicKey
	GateAccount      *wallet.Account
	Pl               *pool.Pool
	Verb             session.ContainerVerb
	Permission       acl.Basic
	Ctx              context.Context
	Session          bool
	ContainerSubject string
	//objectEmitter is used for sending an update of the state of the object's action, e.g send a message that an object has been downloaded.
	//the emitter will be responsible for keeping the UI update on changes. It is not responsible for uniqueness etc
	ContainerEmitter emitter.Emitter
	Attrs            map[string]string
	ActionOperation  eacl.Operation
	ExpiryEpoch      uint64
	EACL             EACLTable
}

func (c ContainerParameter) Read(p []byte) (n int, err error) {
	//TODO implement me
	return 0, errors.New(utils.ErrorWriterNotImplemented)
}

func (c ContainerParameter) Write(p []byte) (n int, err error) {
	//TODO implement me
	return 0, errors.New(utils.ErrorWriterNotImplemented)
}

/*
	type Parameters interface {
		ParentID() string //container ID holder?
		ID() string       //object or container ID holder...
		ForUser() (*wallet.Account, error)
		Name() string
		Attributes() []object.Attribute //need to be able to pass around anything that can be set on the object
		Operation() eacl.Operation
		Epoch() uint64
		Pool() *pool.Pool
		io.ReadWriter //for data transfer pass an interface for a reader and writer. The use then will have the correct type (e.g put or get)
	}
*/
func (c ContainerParameter) ParentID() string {
	return ""
}
func (c ContainerParameter) ID() string {
	return c.Id
}
func (c ContainerParameter) ForUser() (*wallet.Account, error) {
	if c.GateAccount != nil {
		return c.GateAccount, nil
	}
	return nil, errors.New("no gate wallet for object")
}
func (c ContainerParameter) Name() string {
	return c.Description
}

//	func (c ContainerParameter) Attributes() []container.Attribute {
//		return c.Attrs
//	}
func (c ContainerParameter) Operation() eacl.Operation {
	return c.ActionOperation
}
func (c ContainerParameter) Epoch() uint64 {
	return c.ExpiryEpoch
}
func (c ContainerParameter) Pool() *pool.Pool {
	return c.Pl
}

type EACLTable struct {
	ContainerId string   `json:"cid"`
	Records     []Record `json:"records"`
}

type Record struct {
	Action    eacl.Action    `json:"action"`
	Operation eacl.Operation `json:"operation"`
	Filters   []eacl.Filter  `json:"filters"`
	Targets   []Target       `json:"targets"`
}
type Target struct {
	Role       eacl.Role `json:"role"`
	PublicKeys []string  `json:"publicKeys"`
}

func CustomAccessTable(denyPermissions, allowPermissions []string) (eacl.Table, error) {
	// set EACL denying WRITE access to OTHERS
	tab := eacl.Table{}
	var records []eacl.Record
	//this will deny before allow which means that it will block if its in this table and the allow list.
	for _, v := range denyPermissions {
		switch v {
		case "put":
			record := denyOpToOthers(eacl.OperationPut)
			records = append(records, record)
		case "delete":
			record := denyOpToOthers(eacl.OperationDelete)
			records = append(records, record)
		case "head":
			record := denyOpToOthers(eacl.OperationHead)
			records = append(records, record)
		case "get":
			record := denyOpToOthers(eacl.OperationGet)
			records = append(records, record)
		case "search":
			record := denyOpToOthers(eacl.OperationSearch)
			records = append(records, record)
		case "range":
			record := denyOpToOthers(eacl.OperationRange)
			records = append(records, record)
		case "range_hash":
			record := denyOpToOthers(eacl.OperationRangeHash)
			records = append(records, record)
		}
	}
	for _, v := range allowPermissions {
		switch v {
		case "put":
			record := allowOpToOthers(eacl.OperationPut)
			records = append(records, record)
		case "delete":
			record := allowOpToOthers(eacl.OperationDelete)
			records = append(records, record)
		case "head":
			record := allowOpToOthers(eacl.OperationHead)
			records = append(records, record)
		case "get":
			record := allowOpToOthers(eacl.OperationGet)
			records = append(records, record)
		case "search":
			record := allowOpToOthers(eacl.OperationSearch)
			records = append(records, record)
		case "range":
			record := allowOpToOthers(eacl.OperationRange)
			records = append(records, record)
		case "range_hash":
			record := allowOpToOthers(eacl.OperationRangeHash)
			records = append(records, record)
		}
	}
	tab.SetRecords(records)
	return tab, nil
}
func DefaultContainerRestrictionTable(cnrID string) (eacl.Table, error) {
	var cnrId cid.ID
	if err := cnrId.DecodeString(cnrID); err != nil {
		return eacl.Table{}, err
	}
	// set EACL denying WRITE access to OTHERS
	var records []eacl.Record
	operationPutRecord := denyOpToOthers(eacl.OperationPut)
	records = append(records, operationPutRecord)

	pperationDeleteRecord := denyOpToOthers(eacl.OperationDelete)
	records = append(records, pperationDeleteRecord)

	return eacl.NewTableForContainer(cnrId, records), nil
}

// make a neoFS native eacl table from the view table
func ConvertEACLTableToNeoEAcl(eaclTable EACLTable) (*eacl.Table, error) {
	fmt.Printf("converting %+v\r\n", eaclTable)
	var cid cid.ID
	if err := cid.DecodeString(eaclTable.ContainerId); err != nil {
		return nil, fmt.Errorf("invalid container ID: %w", err)
	}
	var records []eacl.Record
	for _, rec := range eaclTable.Records {
		//r := eacl.CreateRecord(rec.Action, rec.Operation)
		var targets []eacl.Target
		for _, t := range rec.Targets { //handles the targets on the record automatically
			//newTarget := eacl.NewTarget()
			//eacl.NewTargetByAccounts()
			//newTarget.SetRole(t.Role)
			var userIds []user.ID
			for _, p := range t.PublicKeys {
				bPubKey, _ := hex.DecodeString(p)
				var pubKey neofsecdsa.PublicKey
				if err := pubKey.Decode(bPubKey); err != nil {
					fmt.Println("error decoding key ", err)
					return nil, err
				}
				publicKey := ecdsa.PublicKey(pubKey)
				userID := user.NewFromECDSAPublicKey(publicKey)
				userIds = append(userIds, userID)
				//eacl.SetTargetECDSAKeys(newTarget, keys...)

			}
			target := eacl.NewTargetByRole(t.Role)
			target.SetAccounts(userIds)

			//targets = append(targets, *newTarget)
			targets = append(targets, target)

		}
		//r.SetTargets(targets...)
		record := eacl.ConstructRecord(rec.Action, rec.Operation, targets)
		records = append(records, record)
	}

	nativeTable := eacl.NewTableForContainer(cid, records)
	fmt.Printf("native table is %+v\r\n", nativeTable)
	return &nativeTable, nil
}
func ConvertNativeToEACLTable(nativeTable eacl.Table) (EACLTable, error) {
	containerID := nativeTable.GetCID()
	eaclTable := EACLTable{
		ContainerId: containerID.String(),
	}
	for _, r := range nativeTable.Records() { // Assuming Records method that returns []eacl.Record
		record := Record{
			Action:    r.Action(),
			Operation: r.Operation(),
			Filters:   r.Filters(), // Assuming Filters method
		}
		for _, t := range r.Targets() { // Assuming Targets method that returns []eacl.Target
			target := Target{
				Role: t.Role(),
			}
			for _, userID := range t.Accounts() {
				// Convert user ID (which is [25]byte) to slice for hex encoding
				binaryUserID := userID[:]
				target.PublicKeys = append(target.PublicKeys, hex.EncodeToString(binaryUserID))
			}
			record.Targets = append(record.Targets, target)
		}
		if len(record.Targets) > 0 { //lets get rid of invalid targets
			eaclTable.Records = append(eaclTable.Records, record)
		}
	}
	return eaclTable, nil
}

type Container struct {
	Name        string            `json:"name"`
	BasicACL    uint32            `json:"basicACL"`
	ExtendedACL EACLTable         `json:"extended_acl"`
	Id          string            `json:"id"`
	Attributes  map[string]string `json:"attributes"`
	Size        float64           `json:"size"`
	DomainName  string            `json:"domainName"`
	DomainZone  string            `json:"domainZone"`
	CreatedAt   int64             `json:"CreatedAt"`
}
type ContainerCaller struct {
	Id        string // Identifier for the object
	CreatedAt time.Time
	UpdatedAt time.Time
	ctx       context.Context
	// the data payload
	//the location its to be read from/saved to if necessary
	ContainerEmitter emitter.Emitter //todo - this needs to tell things its complete (async remember)
	notification.Notifier
	database.Store
}

func (o *ContainerCaller) SetNotifier(notifier notification.Notifier) {
	o.Notifier = notifier
}
func (o *ContainerCaller) SetStore(store database.Store) {
	o.Store = store
}
func (o *ContainerCaller) Delete(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	var sessionToken *session.Container
	if tok, ok := token.(*tokens.ContainerSessionToken); !ok {
		if tok, ok := token.(*tokens.PrivateContainerSessionToken); !ok {
			return errors.New(utils.ErrorNoToken)
		} else {
			sessionToken = tok.SessionToken
		}
	} else {
		sessionToken = tok.SessionToken
	}
	var cnrId cid.ID
	if err := cnrId.DecodeString(p.Id); err != nil {
		actionChan <- o.Notification(
			"failed to decode container Id",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	deleter := client.PrmContainerDelete{}
	deleter.WithinSession(*sessionToken)
	sdkCli, err := p.Pl.RawClient()
	if err != nil {
		return err
	}
	gateSigner := user.NewAutoIDSignerRFC6979(p.GateAccount.PrivateKey().PrivateKey) //fix me is this correct signer?

	wait := waiter.NewContainerDeleteWaiter(sdkCli, waiter.DefaultPollInterval)
	ctx, _ = context.WithTimeout(p.Ctx, 60*time.Second)
	actionChan <- o.Notification(
		"deleting container",
		"deleting container "+p.Id,
		notification.Info,
		notification.ActionToast)
	if err := wait.ContainerDelete(ctx, cnrId, gateSigner, deleter); err != nil {
		actionChan <- o.Notification(
			"failed to delete container",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	localContainer := Container{
		Id: p.Id,
	}
	if err := p.ContainerEmitter.Emit(ctx, emitter.ContainerRemoveUpdate, localContainer); err != nil {
		actionChan <- o.Notification(
			"failed to emit update",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	actionChan <- o.Notification(
		"container deleted",
		p.Id,
		notification.Success,
		notification.ActionToast)
	return nil
}

func (o *ContainerCaller) Create(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	var sessionToken *session.Container
	if tok, ok := token.(*tokens.ContainerSessionToken); !ok {
		if tok, ok := token.(*tokens.PrivateContainerSessionToken); !ok {
			return errors.New(utils.ErrorNoToken)
		} else {
			sessionToken = tok.SessionToken
		}
	} else {
		sessionToken = tok.SessionToken
	}
	const strPolicy = `REP 3`
	var storagePolicy netmap.PlacementPolicy
	err := storagePolicy.DecodeString(strPolicy)
	if err != nil {
		return err
	}
	putter := client.PrmContainerPut{}
	putter.WithinSession(*sessionToken)
	userID := user.NewFromECDSAPublicKey(p.PublicKey)
	fmt.Println("issue check:", session.IssuedBy(*sessionToken, userID))
	var cnr container.Container
	cnr.Init()
	cnr.SetOwner(userID)
	creationTime := time.Now()
	cnr.SetBasicACL(p.Permission) //(p.Permission) //acl.PublicRWExtended)
	cnr.SetCreationTime(creationTime)

	var rd netmap.ReplicaDescriptor
	rd.SetNumberOfObjects(1) // placement policy and replicas definition is required

	var pp netmap.PlacementPolicy
	pp.SetContainerBackupFactor(1)
	pp.SetReplicas([]netmap.ReplicaDescriptor{rd})
	cnr.SetPlacementPolicy(storagePolicy)
	//this should set user specific attributes and not default attributes. I.e block attributes that are 'reserved
	var domain string
	for k, v := range p.Attrs {
		if k == "" || v == "" {
			continue
		}
		if k == "DOMAIN" && strings.HasSuffix(v, ".neo") {
			domain = v
		}
		cnr.SetAttribute(k, v)
	}

	fmt.Println("time check ", creationTime, fmt.Sprint(creationTime.Unix()), strconv.FormatInt(time.Now().Unix(), 10))
	createdAt := time.Now().Unix()
	cnr.SetName(p.Description) //name
	if err := client.SyncContainerWithNetwork(p.Ctx, &cnr, p.Pl); err != nil {
		fmt.Println("sync container with the network state: %s", err)
		actionChan <- o.Notification(
			"Could not create container",
			"Error syncing with network "+err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	gateSigner := user.NewAutoIDSignerRFC6979(p.GateAccount.PrivateKey().PrivateKey) //fix me is this correct signer?
	sdkCli, err := p.Pl.RawClient()
	if err != nil {
		actionChan <- o.Notification(
			"Could not create container",
			"Error connecting to network "+err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	wait := waiter.NewContainerPutWaiter(sdkCli, waiter.DefaultPollInterval)
	ctx, cancel := context.WithTimeout(p.Ctx, 120*time.Second)
	defer cancel()
	actionChan <- o.Notification(
		"creating container",
		"creating container "+p.Name(),
		notification.Info,
		notification.ActionToast)

	idCnr, err := wait.ContainerPut(ctx, cnr, gateSigner, putter)
	fmt.Println("id ", idCnr, "err ", err)
	if err != nil {
		actionChan <- o.Notification(
			"failed to create container",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}

	localContainer := Container{
		Name:       p.Name(),
		Id:         idCnr.String(),
		Attributes: p.Attrs,
		BasicACL:   uint32(p.Permission),
		DomainName: domain, //fixme = domains
		//DomainZone: remoteContainer.ReadDomain().Zone(),
		CreatedAt: createdAt,
	}
	if err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, localContainer); err != nil {
		actionChan <- o.Notification(
			"failed to emit update",
			err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	actionChan <- o.Notification(
		"container "+p.Name()+" created",
		idCnr.String(),
		notification.Success,
		notification.ActionToast)
	return nil
}

func (o *ContainerCaller) Restrict(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	var cnrId cid.ID
	if err := cnrId.DecodeString(p.Id); err != nil {
		actionChan <- o.Notification(
			"failed to decode container Id",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	var sessionToken *session.Container
	if tok, ok := token.(*tokens.ContainerSessionToken); !ok {
		if tok, ok := token.(*tokens.PrivateContainerSessionToken); !ok {
			return errors.New(utils.ErrorNoToken)
		} else {
			sessionToken = tok.SessionToken
		}
	} else {
		sessionToken = tok.SessionToken
	}

	eaclTable, err := ConvertEACLTableToNeoEAcl(p.EACL)
	if err != nil {
		return err
	}
	var setEACLOpts client.PrmContainerSetEACL
	setEACLOpts.WithinSession(*sessionToken)

	sdkCli, err := p.Pl.RawClient()
	if err != nil {
		return err
	}

	setEACLWaiter := waiter.NewContainerSetEACLWaiter(sdkCli, time.Second)

	ctx, cancel := context.WithTimeout(p.Ctx, 120*time.Second)
	defer cancel()
	gateSigner := user.NewAutoIDSignerRFC6979(p.GateAccount.PrivateKey().PrivateKey) //fix me is this correct signer?
	err = setEACLWaiter.ContainerSetEACL(ctx, *eaclTable, gateSigner, setEACLOpts)
	if err != nil {
		return err
	}
	actionChan <- o.Notification(
		"container permissions successfully updated",
		cnrId.String(),
		notification.Success,
		notification.ActionToast)
	return nil
}
func (o *ContainerCaller) SynchronousContainerHead(ctx context.Context, cnrId cid.ID, pl *pool.Pool) (Container, error) {

	var localContainer Container

	var prmGet client.PrmContainerGet
	remoteContainer, err := pl.ContainerGet(ctx, cnrId, prmGet)
	if err != nil {
		return localContainer, err
	}
	sdkCli, err := pl.RawClient()
	if err != nil {
		fmt.Println("could not retrieve pool client ", err)
		return localContainer, err
	}

	var domain string
	if strings.HasSuffix(remoteContainer.Attribute("DOMAIN"), ".neo") {
		domain = remoteContainer.Attribute("DOMAIN")
	}
	//t, err := time.Parse(time.RFC3339, remoteContainer.CreatedAt().Unix())
	//head is going to send a container object, just this time with the content populated
	localContainer = Container{
		BasicACL:   remoteContainer.BasicACL().Bits(),
		Name:       remoteContainer.Name(),
		Id:         cnrId.String(),
		Attributes: make(map[string]string),
		DomainName: domain,
		DomainZone: remoteContainer.ReadDomain().Zone(),
		CreatedAt:  remoteContainer.CreatedAt().Unix(),
	}

	for k, v := range remoteContainer.Attributes() {
		localContainer.Attributes[k] = v
	}
	containerEACL, err := sdkCli.ContainerEACL(ctx, cnrId, client.PrmContainerEACL{})
	if err == nil {

	} else {
		//containerEACL = *eacl.CreateTable(cnrId)
		containerEACL = eacl.NewTableForContainer(cnrId, []eacl.Record{})
	}
	table, err := ConvertNativeToEACLTable(containerEACL)
	if err != nil {
		return localContainer, err
	}
	localContainer.ExtendedACL = table
	return localContainer, nil
}
func (o *ContainerCaller) Head(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, _ tokens.Token) error {
	var cnrId cid.ID
	if err := cnrId.DecodeString(p.Id); err != nil {
		actionChan <- o.Notification(
			"failed to decode container Id",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	localContainer, err := o.SynchronousContainerHead(p.Ctx, cnrId, p.Pl)
	if err != nil {
		actionChan <- o.Notification(
			"failed to retrieve container",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	//todo == this can use the same mechanism (ContainerAddUpdate) as it can supply a full object that just overwrites any existing entry.
	if err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, localContainer); err != nil {
		actionChan <- o.Notification(
			"failed to emit update",
			err.Error(),
			notification.Error,
			notification.ActionNOOP)
		return err
	}
	actionChan <- o.Notification(
		"container head retrieved",
		"container "+p.Id+" head retrieved",
		notification.Info,
		notification.ActionNOOP)
	return nil
}

// List responds with all the IDs of containers owned by the public key.
func (o *ContainerCaller) List(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	var issuer user.ID
	err := issuer.DecodeString(p.ContainerSubject)
	if err != nil {
		issuer = user.NewFromECDSAPublicKey(p.PublicKey)
	}
	fmt.Println("user listing containers", issuer)
	lst := client.PrmContainerList{}
	r, err := p.Pl.ContainerList(ctx, issuer, lst)
	if err != nil {
		actionChan <- o.Notification(
			"Could not list containers",
			err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	//we need to now emit this list one at a time as we receive them (or as one array?)
	for _, v := range r { //we can manage this synchronously i believe.
		err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, Container{Id: v.String()})
		if err != nil {
			fmt.Println("error emitting new object ", p)
			actionChan <- o.Notification(
				"Could not list containers",
				"could not list containers "+err.Error(),
				notification.Error,
				notification.ActionToast)
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

func (c *ContainerCaller) Read(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {

	//var ok bool
	prms := client.PrmObjectSearch{}
	var bToken *bearer.Token
	if token != nil {
		if tok, ok := token.(*tokens.BearerToken); !ok {
			if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
				return errors.New(utils.ErrorNoToken)
			} else {
				bToken = tok.BearerToken
			}
		} else {
			bToken = tok.BearerToken
			prms.WithBearerToken(*tok.BearerToken)
		}
		prms.WithBearerToken(*bToken)
	}

	var cnrId cid.ID
	if err := cnrId.DecodeString(p.Id); err != nil {
		return errors.New(utils.ErrorNotFound) //todo - more specific?
	}

	// todo: list all containers
	//wgMessage := "containerRead"
	//wg.Add(1, wgMessage)
	//go func() {
	//	defer func() {
	//		wg.Done(wgMessage)
	//		fmt.Println("[container] HEAD action completed")
	//	}()

	gateSigner := user.NewAutoIDSignerRFC6979(p.GateAccount.PrivateKey().PrivateKey)

	filter := object.SearchFilters{}
	filter.AddRootFilter()
	prms.SetFilters(filter)
	init, err := p.Pl.ObjectSearchInit(ctx, cnrId, gateSigner, prms)
	if err != nil {
		fmt.Println("err p.Pl.ObjectSearchInit", err)
		actionChan <- c.Notification(
			"failed to list objects",
			"could not list objects "+err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	if err = init.Iterate(func(id oid.ID) bool {
		if err := p.ContainerEmitter.Emit(ctx, emitter.ObjectAddUpdate, object2.Object{Id: id.String(), ParentID: cnrId.String()}); err != nil {
			fmt.Println("emitting object from iterator error ", err)
			actionChan <- c.Notification(
				"failed to iterate objects",
				"could not iterate objects "+err.Error(),
				notification.Error,
				notification.ActionNotification)
			return true
		}
		return false
	}); err != nil {
		fmt.Println("error iterator ", err)
		actionChan <- c.Notification(
			"failed to call object iterator",
			"failed to call object iterator "+err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	}
	//}()

	return nil
}
