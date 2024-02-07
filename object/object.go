package object

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/configwizard/sdk/database"
	"github.com/configwizard/sdk/emitter"
	"github.com/configwizard/sdk/notification"
	"github.com/configwizard/sdk/payload"
	"github.com/configwizard/sdk/readwriter"
	"github.com/configwizard/sdk/tokens"
	"github.com/configwizard/sdk/utils"
	"github.com/configwizard/sdk/waitgroup"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/object/slicer"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"io"
	"log"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const payloadChecksumHeader = "payload_checksum"
const payloadFileType = "filetype"

// isErrAccessDenied is a helpher function for errors from NeoFS
func isErrAccessDenied(err error) (string, bool) {
	unwrappedErr := errors.Unwrap(err)
	for unwrappedErr != nil {
		err = unwrappedErr
		unwrappedErr = errors.Unwrap(err)
	}
	switch err := err.(type) {
	default:
		return "", false
	case apistatus.ObjectAccessDenied:
		return err.Reason(), true
	case *apistatus.ObjectAccessDenied:
		return err.Reason(), true
	}
}

// todo: do we need an interface now if container's handle themselves?
type ObjectParameter struct {
	ContainerId   string
	Id            string
	Description   string
	PublicKey     ecdsa.PublicKey
	GateAccount   *wallet.Account
	Pl            *pool.Pool
	io.ReadWriter //for reading/writing files
	WriteCloser   io.WriteCloser
	//ctx context.Context

	//objectEmitter is used for sending an update of the state of the object's action, e.g send a message that an object has been downloaded.
	//the emitter will be responsible for keeping the UI update on changes. It is not responsible for uniqueness etc
	ObjectEmitter   emitter.Emitter
	Attrs           []object.Attribute
	ActionOperation eacl.Operation
	ExpiryEpoch     uint64
}

func (o ObjectParameter) Name() string {
	return o.Description
}

func (o ObjectParameter) Operation() eacl.Operation {
	return o.ActionOperation
}
func (o ObjectParameter) Epoch() uint64 {
	return o.ExpiryEpoch
}
func (o ObjectParameter) ParentID() string {
	return o.ContainerId
}

func (o ObjectParameter) ID() string {
	return o.Id
}

func (o ObjectParameter) Pool() *pool.Pool {
	return o.Pl
}

func (o ObjectParameter) Attributes() []object.Attribute {
	return o.Attrs
}

func (o ObjectParameter) ForUser() (*wallet.Account, error) {
	if o.GateAccount != nil {
		return o.GateAccount, nil
	}
	return nil, errors.New("no gate wallet for object")
}

type ObjectCaller struct {
	notification.Notifier
	database.Store
	//PublicKey     ecdsa.PublicKey
	//PayloadWriter *slicer.PayloadWriter
	// the data payload
	//the location its to be read from/saved to if necessary
}

// todo - this will need to handle synchronous requests to the database and then asynchronous requests to the network
// basically load what we have but update it.
// these will need to fire notifications and events on completion.
// think about what to return here. We are trying to avoid anything being slow which means if we have something in the database
// we should return that with an 'synchronising' message. then the routine can update the UI for this request using an emitter
// and a message type with any new information?
// however maybe that isn;t the jjob of this and its the hob of the controller, who interfces with the UI. so this needs a chanenl to send messages on actually
func (o *ObjectCaller) Head(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	var objID oid.ID
	if err := objID.DecodeString(p.ID()); err != nil {
		fmt.Println("wrong object Id", err)
		return err
	}
	var cnrID cid.ID
	if err := cnrID.DecodeString(p.ParentID()); err != nil {
		fmt.Println("wrong container Id", err)
		return err
	}
	gA, err := p.ForUser()
	if err != nil {
		return err
	}
	var prmHead client.PrmObjectHead
	fmt.Println("token provided to head ", token, token.(*tokens.BearerToken))
	if tok, ok := token.(*tokens.BearerToken); ok {
		//todo - this could be nil and cause an issue:
		prmHead.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	} else {
		return errors.New("no bearer token provided") //in the future we could offer a session token, but not really recommended.
	}
	fmt.Println("p ---- ", p, p.(ObjectParameter))
	params, ok := p.(ObjectParameter)
	if !ok {
		return errors.New("no object parameters")
	}
	//todo this should be on a routine and send updates to the actionChan. Synchronised currently. (slow)
	gateSigner := user.NewAutoIDSignerRFC6979(gA.PrivateKey().PrivateKey)
	hdr, err := p.Pool().ObjectHead(ctx, cnrID, objID, gateSigner, prmHead)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			fmt.Printf("error here: %s: %s\r\n", err, reason)
			return err
		}
		fmt.Printf("read object header via connection pool: %s", err)
		return err
	}
	id, ok := hdr.ID()
	if !ok {
		return errors.New(utils.ErrorNoID)
	}
	localObject := Object{
		ParentID:   cnrID.String(),
		Id:         id.String(),
		Attributes: make(map[string]string),
		Size:       hdr.PayloadSize(),
		CreatedAt:  time.Time{},
	}
	for _, a := range hdr.Attributes() {
		localObject.Attributes[a.Key()] = a.Value()
	}
	checksum, _ := hdr.PayloadChecksum()
	localObject.Attributes[payloadChecksumHeader] = checksum.String()
	if filename, ok := localObject.Attributes[object.AttributeFileName]; ok {
		localObject.Name = filename
		localObject.Attributes[payloadFileType] = strings.TrimPrefix(filepath.Ext(filename), ".")
	} else {
		localObject.Attributes[payloadFileType] = "" //delete this an check undefined on attributes frontend?, localObject.Attributes) // = "" //breaking changer from "X_EXT"
	}
	if timestamp, ok := localObject.Attributes[object.AttributeTimestamp]; ok {
		//strconv.FormatInt(time.Now().Unix(), 10)
		i, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			panic(err)
		}
		tm := time.UnixMilli(i)
		localObject.CreatedAt = tm //might want to keep this as unix and display on frontend
	}
	if contentType, ok := localObject.Attributes[object.AttributeContentType]; ok {
		localObject.ContentType = contentType
	}
	fmt.Printf("received header object from pool %s -- %+v\r\n", reflect.TypeOf(hdr).String(), localObject)
	//sends this wherever it needs to go. If this is needed somewhere else in the app, then a closure can allow this to be accessed elsewhere in a routine.
	return params.ObjectEmitter.Emit(ctx, emitter.ObjectAddUpdate, localObject)
}
func (o *ObjectCaller) Delete(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	var objID oid.ID
	if err := objID.DecodeString(p.ID()); err != nil {
		fmt.Println("wrong object Id", err)
		return err
	}
	var cnrID cid.ID
	if err := cnrID.DecodeString(p.ParentID()); err != nil {
		fmt.Println("wrong container Id", err)
		return err
	}
	gA, err := p.ForUser()
	if err != nil {
		return err
	}
	params, ok := p.(*ObjectParameter)
	if !ok {
		return errors.New("no object parameters")
	}
	var prmDelete client.PrmObjectDelete
	if tok, ok := token.(*tokens.BearerToken); ok {
		//todo - this could be nil and cause an issue:
		prmDelete.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	} else {
		return errors.New("no bearer token provided")
	}
	gateSigner := user.NewAutoIDSignerRFC6979(gA.PrivateKey().PrivateKey)
	if id, err := p.Pool().ObjectDelete(ctx, cnrID, objID, gateSigner, prmDelete); err != nil {
		return err
	} else {
		return params.ObjectEmitter.Emit(ctx, emitter.ObjectRemoveUpdate, id)
	}
}

func (o *ObjectCaller) List(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	var cnrID cid.ID
	if err := cnrID.DecodeString(p.ParentID()); err != nil {
		fmt.Println("wrong container Id", err)
		return err
	}
	gA, err := p.ForUser()
	if err != nil {
		return err
	}
	prmList := client.PrmObjectSearch{}
	if tok, ok := token.(*tokens.BearerToken); ok {
		//todo - this could be nil and cause an issue:
		prmList.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	} else {
		return errors.New("no bearer token provided")
	}
	filter := object.SearchFilters{}
	filter.AddRootFilter()
	prmList.SetFilters(filter)
	gateSigner := user.NewAutoIDSignerRFC6979(gA.PrivateKey().PrivateKey)
	init, err := p.Pool().ObjectSearchInit(ctx, cnrID, gateSigner, prmList)
	if err != nil {
		return err
	}
	var iterationError error
	if err = init.Iterate(func(id oid.ID) bool {
		if metaError := o.Head(wg, ctx, p, actionChan, token); metaError != nil {
			iterationError = metaError
			return true
		}
		//head will emit on list's behalf with the data
		return false
	}); err != nil {
		return err
	}
	return iterationError
}

// tmpPreRequisite should be run before trying to retrieve an object. It provides the size of the object and the reader that will do the retrieval.
func InitReader(ctx context.Context, params ObjectParameter, token tokens.Token) (object.Object, io.ReadCloser, error) {
	var objID oid.ID
	if err := objID.DecodeString(params.ID()); err != nil {
		fmt.Println("wrong object Id", err)
		return object.Object{}, nil, err
	}
	var cnrID cid.ID
	if err := cnrID.DecodeString(params.ParentID()); err != nil {
		fmt.Println("wrong container Id", err)
		return object.Object{}, nil, err
	}
	gA, err := params.ForUser()
	if err != nil {
		return object.Object{}, nil, err
	}
	gateSigner := user.NewAutoIDSigner(gA.PrivateKey().PrivateKey) //fix me is this correct signer?
	getInit := client.PrmObjectGet{}
	if tok, ok := token.(*tokens.BearerToken); ok {
		//todo - this could be nil and cause an issue:
		getInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	} else {
		return object.Object{}, nil, errors.New("no bearer token provided")
	}

	dstObject, objReader, err := params.Pool().ObjectGetInit(ctx, cnrID, objID, gateSigner, getInit)
	if err != nil {
		log.Println("error creating object reader ", err)
		return object.Object{}, nil, err
	}
	//the object reader will need closing.
	//might need a before(), during(), after() type interface to do this potentially, but not nice. Potentially attach the
	//dstObject to the parameters so that can be closed in the during() phase.
	//todo: readers and writers should be attached to the object that owns the method
	return dstObject, objReader, nil
}

func (o ObjectCaller) Read(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	buf := make([]byte, 1024)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			if _, err := p.Write(buf[:n]); err != nil {
				actionChan <- o.Notification(
					"failed to write to buffer",
					err.Error(),
					notification.Error,
					notification.ActionNotification)
				return err
			}
		}
		if err != nil {
			if err == io.EOF {
				fmt.Println("reached end of file")
				actionChan <- o.Notification(
					"download complete!",
					"object "+p.ID()+" completed",
					notification.Success,
					notification.ActionNotification)
				break
			}
			fmt.Println("actual error ", err)
			actionChan <- o.Notification(
				"error",
				err.Error(),
				notification.Error,
				notification.ActionNotification)
			return err
		}
	}
	//no need to emit anything - the progress bar will update the UI for us.
	return nil
}
func CloseReader(objReader io.ReadCloser) error {
	//fixme - this needs to occur for the object to finish.
	return objReader.Close()
}

func InitWriter(ctx context.Context, p *ObjectParameter, token tokens.Token) (io.WriteCloser, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(p.ParentID()); err != nil {
		fmt.Println("wrong container Id", err)
		return nil, err
	}
	fmt.Println("init writing for container ID ", cnrID.String())
	gA, err := p.ForUser()
	if err != nil {
		return nil, err
	}

	sdkCli, err := p.Pool().RawClient()
	if err != nil {
		return nil, err
	}
	userID := user.ResolveFromECDSAPublicKey(p.PublicKey)
	var gateSigner user.Signer = user.NewAutoIDSignerRFC6979(gA.PrivateKey().PrivateKey)
	ni, err := sdkCli.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return nil, fmt.Errorf("network info: %w", err)
	}
	var opts slicer.Options
	opts.SetObjectPayloadLimit(ni.MaxObjectSize())
	opts.SetCurrentNeoFSEpoch(ni.CurrentEpoch())
	if tok, ok := token.(*tokens.BearerToken); ok {
		//todo - this could be nil and cause an issue:
		if !tok.BearerToken.VerifySignature() {
			fmt.Println("ERROR Signature not verified!!!")
			return nil, errors.New("TOKEN IS NOT VERIFIED!!!!")
		}
		opts.SetBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	} else {
		return nil, errors.New("no bearer token provided")
	}
	if !ni.HomomorphicHashingDisabled() {
		opts.CalculateHomomorphicChecksum()
	}
	var hdr object.Object
	hdr.SetContainerID(cnrID)
	hdr.SetType(object.TypeRegular)
	hdr.SetOwnerID(&userID)
	hdr.SetCreationEpoch(ni.CurrentEpoch())
	plWriter, err := slicer.InitPut(ctx, sdkCli, hdr, gateSigner, opts)
	if err != nil {
		fmt.Println("error creating putter ", err)
		return nil, err
	}
	//p.Id = plWriter.ID().String() //store this back on the object so we can access it later.
	p.WriteCloser = plWriter
	return plWriter, err
}

func (o ObjectCaller) Write(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	objectParameters, ok := p.(ObjectParameter)
	if ok {
		var err error
		objectWriteCloser, err := InitWriter(ctx, &objectParameters, token)
		if err != nil {
			return err
		}
		if ds, ok := objectParameters.ReadWriter.(*readwriter.DualStream); ok {
			ds.Writer = objectWriteCloser
		} else {
			return err
		}
	}

	buf := make([]byte, 1024)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			if _, err := p.Write(buf[:n]); err != nil {
				actionChan <- o.Notification(
					"failed to write to buffer",
					err.Error(),
					notification.Error,
					notification.ActionNotification)
				return err
			}
		}
		if err != nil {
			if err == io.EOF {

				break
			}
			fmt.Println("actual error ", err)
			actionChan <- o.Notification(
				"error",
				err.Error(),
				notification.Error,
				notification.ActionNotification)
			return err
		}
	}
	if tok, ok := token.(*tokens.BearerToken); ok {
		//todo - this could be nil and cause an issue:
		if !tok.BearerToken.VerifySignature() {
			fmt.Println("ERROR Signature not verified!!!")
			return errors.New("TOKEN IS NOT VERIFIED!!!!")
		} else {
			j, _ := json.MarshalIndent(tok.BearerToken, "", " ")
			fmt.Printf("verified %s\n", j)
			fmt.Printf("table %+v\r\n", tok.BearerToken.EACLTable())
		}
	}
	if err := objectParameters.WriteCloser.Close(); err != nil {
		var errAccess apistatus.ObjectAccessDenied
		if errors.Is(err, &errAccess) {
			fmt.Println("access reason:", errAccess.Error())
		}
		fmt.Println("error closing writeCloser ", err)
		return err
	}
	if payloadWriter, ok := objectParameters.WriteCloser.(*slicer.PayloadWriter); ok {
		objectParameters.Id = payloadWriter.ID().String()
		fmt.Println("pushing data for container ", p.ParentID())
		fmt.Println("reached end of file, ", objectParameters.Id)
	}
	fmt.Println("reached end of file, ", p.ID())
	actionChan <- o.Notification(
		"upload complete!",
		"object "+p.ID()+" completed", //we gleaned the ID during the write initiator.
		notification.Success,
		notification.ActionNotification)
	//if oParameter, ok := p.(ObjectParameter); ok {
	//
	//} else {
	//	return errors.New("could not retrieve ID of object")
	//}
	return nil
}

//
//// this might need to become an interface function unless we have an object manager that the controller calls.
//func (o Object) CloseWriter(wg *sync.WaitGroup, p ObjectParameter, actionChan chan notification.NewNotification, token tokens.Token) (oid.ID, error) {
//	if err := o.PayloadWriter.Close(); err != nil {
//		return oid.ID{}, err
//	}
//	//todo: add this object to the database, once retrieved information
//	//Id := o.PayloadWriter.ID()
//	//p.Id = Id.String() //decoded other end. Perhaps inefficient but need to set it now so that we can retrieve its metadata
//	//return o.Head(wg, p, actionChan, token)
//	return o.PayloadWriter.ID(), nil
//}

type Object struct {
	ParentID    string            `json:"parentID"`
	Name        string            `json:"name"`
	Id          string            `json:"id"`
	ContentType string            `json:"contentType"`
	Attributes  map[string]string `json:"attributes"`
	Size        uint64            `json:"size"`
	CreatedAt   time.Time         `json:"CreatedAt"`
}
