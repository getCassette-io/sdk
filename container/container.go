package container

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/configwizard/sdk/database"
	"github.com/configwizard/sdk/emitter"
	"github.com/configwizard/sdk/notification"
	object2 "github.com/configwizard/sdk/object"
	"github.com/configwizard/sdk/payload"
	"github.com/configwizard/sdk/tokens"
	"github.com/configwizard/sdk/utils"
	"github.com/configwizard/sdk/waitgroup"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	v2Container "github.com/nspcc-dev/neofs-api-go/v2/container"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/container"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/netmap"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"github.com/nspcc-dev/neofs-sdk-go/waiter"
	"log"
	"strconv"
	"time"
)

const (
	attributeName      = "Name"
	attributeTimestamp = "Timestamp"
)

type ContainerParameter struct {
	Id          string
	Description string
	PublicKey   ecdsa.PublicKey
	GateAccount *wallet.Account
	Pl          *pool.Pool
	Verb        session.ContainerVerb
	Permission  acl.Basic
	Ctx         context.Context
	Session     bool

	//objectEmitter is used for sending an update of the state of the object's action, e.g send a message that an object has been downloaded.
	//the emitter will be responsible for keeping the UI update on changes. It is not responsible for uniqueness etc
	ContainerEmitter emitter.Emitter
	Attrs            []v2Container.Attribute
	ActionOperation  eacl.Operation
	ExpiryEpoch      uint64
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

type Container struct {
	Name       string            `json:"name"`
	BasicACL   uint32            `json:"basicACL"`
	Id         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
	Size       float64           `json:"size"`
	DomainName string            `json:"domainName"`
	DomainZone string            `json:"domainZone"`
	CreatedAt  time.Time         `json:"CreatedAt"`
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

func connectToNeoFS(endpoint string) (*client.Client, error) {
	neoFSClient, err := client.New(client.PrmInit{})
	if err != nil {
		return nil, err
	}
	var dialPrm client.PrmDial
	dialPrm.SetServerURI(endpoint)

	err = neoFSClient.Dial(dialPrm)
	return neoFSClient, err
}

func (o *ContainerCaller) Create(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	tok, ok := token.(*tokens.ContainerSessionToken)
	if !ok {
		return errors.New(utils.ErrorNoToken)
	}
	j, _ := json.MarshalIndent(tok, "", " ")
	fmt.Printf("verified %s\n", j)
	fmt.Printf("table %+v\r\n", tok)

	const strPolicy = `REP 1`
	var storagePolicy netmap.PlacementPolicy
	err := storagePolicy.DecodeString(strPolicy)
	if err != nil {
		return err
	}
	putter := client.PrmContainerPut{}
	putter.WithinSession(*tok.SessionToken)
	userID := user.ResolveFromECDSAPublicKey(p.PublicKey)
	fmt.Println("issue check:", session.IssuedBy(*tok.SessionToken, userID))
	var cnr container.Container
	cnr.Init()
	cnr.SetOwner(userID)
	creationTime := time.Now()
	cnr.SetBasicACL(acl.PublicRWExtended) //(p.Permission) //acl.PublicRWExtended)
	cnr.SetCreationTime(creationTime)

	var rd netmap.ReplicaDescriptor
	rd.SetNumberOfObjects(1) // placement policy and replicas definition is required

	var pp netmap.PlacementPolicy
	pp.SetContainerBackupFactor(1)
	pp.AddReplicas(rd)

	cnr.SetPlacementPolicy(storagePolicy)

	var containerAttributes = make(map[string]string) //todo shift this up to the javascript side
	//this should set user specific attributes and not default attributes. I.e block attributes that are 'reserved
	for k, v := range containerAttributes {
		cnr.SetAttribute(k, v)
	}
	fmt.Println("time check ", creationTime, fmt.Sprint(creationTime.Unix()), strconv.FormatInt(time.Now().Unix(), 10))
	createdAt := time.Now()
	cnr.SetName(p.Description) //name
	if err := client.SyncContainerWithNetwork(p.Ctx, &cnr, p.Pl); err != nil {
		fmt.Println("sync container with the network state: %s", err)
		return err
	}
	gateSigner := user.NewAutoIDSignerRFC6979(p.GateAccount.PrivateKey().PrivateKey) //fix me is this correct signer?
	//sdkCli, err := p.Pl.RawClient()
	//if err != nil {
	//	fmt.Println("error raw client ", err)
	//	return err //handle this error
	//}
	cli, err := connectToNeoFS("grpcs://st4.storage.fs.neo.org:8082")
	if err != nil {
		return err
	}
	cnrJson, _ := cnr.MarshalJSON()
	fmt.Printf("owner %+v - cnrJson %+v\r\n", cnr.Owner(), string(cnrJson))
	wait := waiter.NewContainerPutWaiter(cli, waiter.DefaultPollInterval)
	ctx, cancel := context.WithTimeout(p.Ctx, 120*time.Second)
	defer cancel()
	fmt.Println("about to begin container put")
	idCnr, err := wait.ContainerPut(ctx, cnr, gateSigner, putter)
	fmt.Println("id ", idCnr, "err ", err)
	if err != nil {
		fmt.Println("error putting container ", err)
		actionChan <- o.Notification(
			"failed to create container",
			err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	localContainer := Container{
		Name:       p.Name(),
		Id:         idCnr.String(),
		Attributes: containerAttributes, //make(map[string]string),
		BasicACL:   uint32(p.Permission),
		//DomainName: remoteContainer.ReadDomain().Name(), //fixme = domains
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
		"container created",
		"container "+idCnr.String()+" created",
		notification.Success,
		notification.ActionNotification)
	return nil
}

func (o *ContainerCaller) Head(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, _ tokens.Token) error {
	var cnrId cid.ID
	fmt.Println("decoding ", p.Id)
	if err := cnrId.DecodeString(p.Id); err != nil {
		actionChan <- o.Notification(
			"failed to decode container Id",
			err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	var prmGet client.PrmContainerGet
	remoteContainer, err := p.Pl.ContainerGet(ctx, cnrId, prmGet)
	if err != nil {
		actionChan <- o.Notification(
			"failed to retrieve container",
			err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	//head is going to send a container object, just this time with the content populated
	localContainer := Container{
		BasicACL:   remoteContainer.BasicACL().Bits(),
		Name:       remoteContainer.Name(),
		Id:         p.Id,
		Attributes: make(map[string]string),
		DomainName: remoteContainer.ReadDomain().Name(),
		DomainZone: remoteContainer.ReadDomain().Zone(),
		CreatedAt:  remoteContainer.CreatedAt(),
	}
	remoteContainer.IterateAttributes(func(k string, v string) {
		fmt.Println("populating for ", k, v)
		localContainer.Attributes[k] = v
	})
	//todo == this can use the same mechanism (ContainerAddUpdate) as it can supply a full object that just overwrites any existing entry.
	if err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, localContainer); err != nil {
		actionChan <- o.Notification(
			"failed to emit update",
			err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	actionChan <- o.Notification(
		"container head retrieved!",
		"container "+p.Id+" head retrieved",
		notification.Success,
		notification.ActionNotification)
	return nil
}

// List responds with all the IDs of containers owned by the public key.
func (o *ContainerCaller) List(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	userID := user.ResolveFromECDSAPublicKey(p.PublicKey)
	fmt.Println("user id is....", userID)
	lst := client.PrmContainerList{}
	lst.WithXHeaders() //fixme - dis
	fmt.Println("getting list with ", lst)
	r, err := p.Pl.ContainerList(ctx, userID, lst)
	if err != nil {
		actionChan <- o.Notification(
			"failed to list containers",
			"could not list containers "+err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	log.Printf("%v\r\n", r)
	//we need to now emit this list one at a time as we receive them (or as one array?)
	for _, v := range r { //we can manage this synchronously i believe.
		fmt.Printf("emitting here %+v\r\n", v.String())
		err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, Container{Id: v.String()})
		if err != nil {
			fmt.Println("error emitting new object ", p)
			actionChan <- o.Notification(
				"failed to list containers",
				"could not list containers "+err.Error(),
				notification.Error,
				notification.ActionNotification)
		}
		////put this on a channel?
		//if metaError := o.Head(wg, ctx, p, actionChan, token); metaError != nil {
		//	actionChan <- o.Notification(
		//		"failed to retrieve metadata for"+v.String(),
		//		"could not list containers "+err.Error(),
		//		notification.Error,
		//		notification.ActionNotification)
		//	continue
		//}
		time.Sleep(100 * time.Millisecond)
	}
	actionChan <- o.Notification(
		"container list complete!",
		"container list retrieved",
		notification.Success,
		notification.ActionToast)
	//wgMessage := "containerList"
	//wg.Add(1, wgMessage)
	//go func() {
	//	defer func() {
	//		wg.Done(wgMessage)
	//		fmt.Println("[container] List action completed")
	//	}()
	//	fmt.Println("user id....", p.PublicKey)
	//	userID := user.ResolveFromECDSAPublicKey(p.PublicKey)
	//	fmt.Println("user id is....", userID)
	//	lst := client.PrmContainerList{}
	//	lst.WithXHeaders() //fixme - discover what this is for
	//	var exit bool
	//	for {
	//		select {
	//		case <-ctx.Done():
	//			fmt.Println("mock head exited")
	//			return
	//		default:
	//			fmt.Println("getting list with ", lst)
	//			r, err := p.Pl.ContainerList(ctx, userID, lst)
	//			if err != nil {
	//				actionChan <- o.Notification(
	//					"failed to list containers",
	//					"could not list containers "+err.Error(),
	//					notification.Error,
	//					notification.ActionNotification)
	//				return
	//			}
	//			log.Printf("%v\r\n", r)
	//			//we need to now emit this list one at a time as we receive them (or as one array?)
	//			for _, v := range r {
	//				fmt.Printf("emitting %+v\r\n", v)
	//				err := p.ContainerEmitter.Emit(p.ctx, emitter.ContainerListUpdate, v)
	//				if err != nil {
	//					fmt.Println("error emitting new object ", p)
	//					actionChan <- o.Notification(
	//						"failed to list containers",
	//						"could not list containers "+err.Error(),
	//						notification.Error,
	//						notification.ActionNotification)
	//				}
	//				time.Sleep(100 * time.Millisecond)
	//			}
	//			exit = true
	//			break
	//		}
	//		if exit {
	//			actionChan <- o.Notification(
	//				"list complete!",
	//				"object "+o.Id+" completed",
	//				notification.Success,
	//				notification.ActionNotification)
	//			return
	//		}
	//	}
	//}()
	return nil
}

func (o *ContainerCaller) Delete(p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) (notification.NewNotification, error) {
	return notification.NewNotification{}, nil
}
func (o *ContainerCaller) Read(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {

	tok, ok := token.(*tokens.BearerToken)
	if !ok {
		return errors.New(utils.ErrorNoToken)
	}
	var cnrId cid.ID
	fmt.Println("decoding ", p.Id)
	if err := cnrId.DecodeString(p.Id); err != nil {
		return errors.New(utils.ErrorNotFound) //todo - more specific?
	}

	// todo: list all containers
	wgMessage := "containerRead"
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			fmt.Println("[container] HEAD action completed")
		}()
		//var exit bool
		//select {
		//case <-ctx.Done():
		//	fmt.Println("contqiner read exited")
		//	return
		//default:
		gateSigner := user.NewAutoIDSignerRFC6979(p.GateAccount.PrivateKey().PrivateKey)

		prms := client.PrmObjectSearch{}
		prms.WithBearerToken(*tok.BearerToken) //fixme - why is this a pointer?

		filter := object.SearchFilters{}
		filter.AddRootFilter()
		prms.SetFilters(filter)
		init, err := p.Pl.ObjectSearchInit(ctx, cnrId, gateSigner, prms)
		if err != nil {
			fmt.Println("err p.Pl.ObjectSearchInit", err)
			actionChan <- o.Notification(
				"failed to list objects",
				"could not list objects "+err.Error(),
				notification.Error,
				notification.ActionNotification)
			return
		}
		if err = init.Iterate(func(id oid.ID) bool {
			fmt.Println("received ", id.String())
			//similar to containers, we need to get the head of an object now.
			//the container emitter can inform an object emitter (if needs be) that a new object is available for the UI
			//before retrieving data about the object.
			if err := p.ContainerEmitter.Emit(ctx, emitter.ObjectAddUpdate, object2.Object{Id: id.String(), ParentID: cnrId.String()}); err != nil {
				fmt.Println("emitting object from iterator error ", err)
				actionChan <- o.Notification(
					"failed to iterate objects",
					"could not iterate objects "+err.Error(),
					notification.Error,
					notification.ActionNotification)
				return true
			}
			return false
		}); err != nil {
			fmt.Println("error iterator ", err)
			actionChan <- o.Notification(
				"failed to call object iterator",
				"failed to call object iterator "+err.Error(),
				notification.Error,
				notification.ActionNotification)
			return
		}
		//retrieveContainers := views.SimulateNeoFS(views.Containers, "") // Get the content based on the selected item
		//for _, v := range retrieveContainers {
		//	err := p.ContainerEmitter.Emit(ctx, string(emitter.ContainerListUpdate), v)
		//	if err != nil {
		//		fmt.Println("error emitting new object ", p)
		//		actionChan <- o.Notification(
		//			"failed to list containers",
		//			"could not list containers "+err.Error(),
		//			notification.Error,
		//			notification.ActionNotification)
		//		return
		//	}
		//	time.Sleep(100 * time.Millisecond)
		//}
		actionChan <- o.Notification(
			"container object list complete!",
			"object list for "+o.Id+" finished",
			notification.Success,
			notification.ActionToast)
		//exit = true
		//break
		//}
		//if exit {
		//		actionChan <- o.Notification(
		//			"container object list complete!",
		//			"object list for "+o.Id+" finished",
		//			notification.Success,
		//			notification.ActionToast)
		//	return
		//}
		//return nil
	}()

	return nil
}
