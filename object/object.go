package object

import (
	"context"
	"crypto/ecdsa"
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
	"go.uber.org/zap"
	"io"
	"log"
	"strconv"
	"time"
)

type ObjectAction interface {
	SynchronousObjectHead(ctx context.Context, cnrId cid.ID, objID oid.ID, signer user.Signer, pl *pool.Pool) (Object, error)
	SearchHeadByAttribute(ctx context.Context, cnrId cid.ID, attribute object.Attribute, signer user.Signer, pl *pool.Pool) (Object, error)
	Head(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error
	Create(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error
	Read(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error
	List(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error
	Delete(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error
	SetNotifier(notifier notification.Notifier) // Assuming NotifierType is the type for Notifier
	SetStore(store database.Store)              // Assuming StoreType is the type for Store
}

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

func (o *ObjectCaller) SetNotifier(notifier notification.Notifier) {
	o.Notifier = notifier
}
func (o *ObjectCaller) SetStore(store database.Store) {
	o.Store = store
}

func (o *ObjectCaller) SynchronousObjectHead(ctx context.Context, cnrId cid.ID, objID oid.ID, signer user.Signer, pl *pool.Pool) (Object, error) {
	var prmHead client.PrmObjectHead
	fmt.Printf("ids %s - %s\n", cnrId.String(), objID.String())
	//retrieving an object head is public
	hdr, err := pl.ObjectHead(ctx, cnrId, objID, signer, prmHead)
	if err != nil {
		if reason, ok := isErrAccessDenied(err); ok {
			fmt.Printf("error here: %s: %s\r\n", err, reason)
			return Object{}, err
		}
		fmt.Printf("read object header via connection pool: %s", err)
		return Object{}, err
	}
	id, ok := hdr.ID()
	if !ok {
		return Object{}, err
	}
	localObject := Object{
		ParentID:   cnrId.String(),
		Id:         id.String(),
		Size:       hdr.PayloadSize(),
		CreatedAt:  time.Time{}.Unix(),
		Attributes: make(map[string]string),
	}
	for _, v := range hdr.Attributes() {
		switch v.Key() {
		case object.AttributeTimestamp:
			timestampInt, err := strconv.ParseInt(v.Value(), 10, 64)
			if err != nil {
				fmt.Println("Error converting string to int:", err)
				return Object{}, err
			}
			localObject.CreatedAt = timestampInt
		case object.AttributeContentType:
			localObject.ContentType = v.Value()
		case object.AttributeFileName:
			localObject.Name = v.Value()
		case object.AttributeExpirationEpoch:
			//nothing yet
		case object.AttributeFilePath:
			//nothing yetm
		}
		localObject.Attributes[v.Key()] = v.Value()
	}
	checksum, _ := hdr.PayloadChecksum()
	localObject.Attributes[payloadChecksumHeader] = checksum.String()

	return localObject, nil
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
	if token != nil {
		if tok, ok := token.(*tokens.BearerToken); !ok {
			if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
				return errors.New(utils.ErrorNoToken) //in the future we could offer a session token, but not really recommended.
			} else {
				prmHead.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
			}
		} else {
			prmHead.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
		}
	}
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
		Size:       hdr.PayloadSize(),
		CreatedAt:  time.Time{}.Unix(),
		Attributes: make(map[string]string),
	}
	for _, v := range hdr.Attributes() {
		switch v.Key() {
		case object.AttributeTimestamp:
			timestampInt, err := strconv.ParseInt(v.Value(), 10, 64)
			if err != nil {
				fmt.Println("Error converting string to int:", err)
				return err
			}
			localObject.CreatedAt = timestampInt
		case object.AttributeContentType:
			localObject.ContentType = v.Value()
		case object.AttributeFileName:
			localObject.Name = v.Value()
		case object.AttributeExpirationEpoch:
			//nothing yet
		case object.AttributeFilePath:
			//nothing yet
		}
		localObject.Attributes[v.Key()] = v.Value()
	}
	checksum, _ := hdr.PayloadChecksum()
	localObject.Attributes[payloadChecksumHeader] = checksum.String()

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
	params, ok := p.(ObjectParameter)
	if !ok {
		return errors.New("no object parameters")
	}
	var prmDelete client.PrmObjectDelete
	if token != nil {
		if tok, ok := token.(*tokens.BearerToken); !ok {
			if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
				return errors.New("no bearer token provided")
			} else {
				prmDelete.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
			}
		} else {
			prmDelete.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
		}
	}
	gateSigner := user.NewAutoIDSignerRFC6979(gA.PrivateKey().PrivateKey)
	ctx, _ = context.WithTimeout(ctx, 60*time.Second)
	actionChan <- o.Notification(
		"deleting object",
		"deleting object "+objID.String(),
		notification.Info,
		notification.ActionToast)
	if _, err := p.Pool().ObjectDelete(ctx, cnrID, objID, gateSigner, prmDelete); err != nil {
		actionChan <- o.Notification(
			"delete failed",
			"object "+p.ID()+" failed to delete "+err.Error(),
			notification.Error,
			notification.ActionToast)
		return err
	} else {
		localObject := Object{
			ParentID: p.ParentID(),
			Id:       p.ID(),
		}
		if err := params.ObjectEmitter.Emit(ctx, emitter.ObjectRemoveUpdate, localObject); err != nil {
			fmt.Println("could not emit update", err)
		}
		actionChan <- o.Notification(
			"delete complete",
			"object "+p.ID()+" deleted",
			notification.Success,
			notification.ActionNotification)
	}
	return nil
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

// search a container by attribute -- currently only for public requests through the browser.
func (o *ObjectCaller) SearchHeadByAttribute(ctx context.Context, cnrID cid.ID, attr object.Attribute, signer user.Signer, pl *pool.Pool) (Object, error) {
	//var cnrID cid.ID
	//if err := cnrID.DecodeString(params.ParentID()); err != nil {
	//	fmt.Println("wrong container Id", err)
	//	return Object{}, err
	//}

	//if len(params.Attributes()) == 0 {
	//	return Object{}, errors.New("need an attribute to search by")
	//}
	//filter only by single attribute for now
	//attribute := params.Attributes()[0]
	filters := object.NewSearchFilters()
	filters.AddRootFilter()
	filters.AddFilter(attr.Key(), attr.Value(), object.MatchStringEqual)

	var prm client.PrmObjectSearch
	prm.SetFilters(filters)
	//gA, err := params.ForUser()
	//if err != nil {
	//	return Object{}, err
	//}
	//gateSigner := user.NewAutoIDSigner(gA.PrivateKey().PrivateKey) //fix me is this correct signer?
	//rangeInit := client.PrmObjectRange{}
	//if token != nil {
	//	if tok, ok := token.(*tokens.BearerToken); !ok {
	//		if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
	//			return Object{}, errors.New("no bearer token provided")
	//		} else {
	//			rangeInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	//		}
	//	} else {
	//		rangeInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
	//	}
	//}
	res, err := pl.ObjectSearchInit(ctx, cnrID, signer, prm)
	if err != nil {
		return Object{}, err
	}
	defer func() {
		if err = res.Close(); err != nil {
			zap.L().Error("failed to close resource", zap.Error(err))
		}
	}()

	buf := make([]oid.ID, 1)

	n, _ := res.Read(buf)
	if n == 0 {
		err = res.Close()

		if err == nil || errors.Is(err, io.EOF) {
			return Object{}, errors.New("object not found")
		}
		return Object{}, errors.New("read object list failed")
	}
	//possibly convoluted as its an ID anyway, but whatevs. Stolen from rest API
	var addrObj oid.Address
	addrObj.SetContainer(cnrID)
	addrObj.SetObject(buf[0])
	return o.SynchronousObjectHead(ctx, cnrID, addrObj.Object(), signer, pl)
}
func Ranger(ctx context.Context, params ObjectParameter, token tokens.Token) error {
	var objID oid.ID
	if err := objID.DecodeString(params.ID()); err != nil {
		fmt.Println("wrong object Id", err)
		return err
	}
	var cnrID cid.ID
	if err := cnrID.DecodeString(params.ParentID()); err != nil {
		fmt.Println("wrong container Id", err)
		return err
	}
	gA, err := params.ForUser()
	if err != nil {
		return err
	}
	gateSigner := user.NewAutoIDSigner(gA.PrivateKey().PrivateKey) //fix me is this correct signer?
	rangeInit := client.PrmObjectRange{}
	if token != nil {
		if tok, ok := token.(*tokens.BearerToken); !ok {
			if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
				return errors.New("no bearer token provided")
			} else {
				rangeInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
			}
		} else {
			rangeInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
		}
	}
	offset := uint64(100)
	length := uint64(100)
	objRangeReader, err := params.Pool().ObjectRangeInit(ctx, cnrID, objID, offset, length, gateSigner, rangeInit)
	if err != nil {
		log.Println("error creating object reader ", err)
		return err
	}

	var buf []byte
	_, err = objRangeReader.Read(buf)
	if err != nil {
		return err
	}
	params.ObjectEmitter.Emit(ctx, emitter.ObjectRangeUpdate, buf)
	return nil
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
	if token != nil {
		if tok, ok := token.(*tokens.BearerToken); !ok {
			if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
				return object.Object{}, nil, errors.New("no bearer token provided")
			} else {
				getInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
			}
		} else {
			getInit.WithBearerToken(*tok.BearerToken) //now we know its a bearer token we can extract it
		}
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

	objectParameters, ok := p.(ObjectParameter)
	if ok {
		_, objectReader, err := InitReader(ctx, objectParameters, token)
		if err != nil {
			return err
		}
		if ds, ok := objectParameters.ReadWriter.(*readwriter.DualStream); ok {
			ds.Reader = objectReader
		} else {
			return errors.New("not a dual stream")
		}
	}

	buf := make([]byte, 1024)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			if _, err := p.Write(buf[:n]); err != nil {
				actionChan <- o.Notification(
					"failed to write data",
					err.Error(),
					notification.Error,
					notification.ActionToast)
				return err
			}
		}
		if err != nil {
			if err == io.EOF {
				fmt.Println("reached end of file")
				actionChan <- o.Notification(
					"download complete",
					"object "+p.ID()+" completed",
					notification.Success,
					notification.ActionToast)
				break
			}
			actionChan <- o.Notification(
				"error",
				err.Error(),
				notification.Error,
				notification.ActionToast)
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

	if token != nil {
		if tok, ok := token.(*tokens.BearerToken); !ok {
			if tok, ok := token.(*tokens.PrivateBearerToken); !ok {
				return nil, errors.New("no bearer token provided")
			} else {
				opts.SetBearerToken(*tok.BearerToken)
			}
		} else {
			opts.SetBearerToken(*tok.BearerToken)
		}
	}

	if !ni.HomomorphicHashingDisabled() {
		opts.CalculateHomomorphicChecksum()
	}
	var hdr object.Object
	hdr.SetContainerID(cnrID)
	hdr.SetType(object.TypeRegular)
	hdr.SetOwnerID(&userID)
	hdr.SetCreationEpoch(ni.CurrentEpoch())
	fmt.Println("configuring header for new object ", p.Attrs)

	var timestampAttr object.Attribute
	timestampAttr.SetKey(object.AttributeTimestamp)
	timestampAttr.SetValue(strconv.FormatInt(time.Now().Unix(), 10))

	p.Attrs = append(p.Attrs, timestampAttr)

	hdr.SetAttributes(p.Attrs...)
	plWriter, err := slicer.InitPut(ctx, sdkCli, hdr, gateSigner, opts)
	if err != nil {
		fmt.Println("error creating putter ", err)
		return nil, err
	}
	p.WriteCloser = plWriter
	return plWriter, err
}

func (o ObjectCaller) Create(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	fmt.Println("beginning to write object")
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
					"failed to write data",
					err.Error(),
					notification.Error,
					notification.ActionToast)
				return err
			}
		}
		if err != nil {
			if err == io.EOF {

				break
			}
			actionChan <- o.Notification(
				"error",
				err.Error(),
				notification.Error,
				notification.ActionToast)
			return err
		}
	}

	var payloadWriter *slicer.PayloadWriter
	if payloadWriter, ok = objectParameters.WriteCloser.(*slicer.PayloadWriter); !ok {
		actionChan <- o.Notification(
			"upload failed",
			"object "+p.ID()+" failed to upload", //we gleaned the ID during the write initiator.
			notification.Error,
			notification.ActionToast)
		return errors.New("could retriever the writer.")
	} else {
		if err := payloadWriter.Close(); err != nil {
			var errAccess apistatus.ObjectAccessDenied
			if errors.Is(err, &errAccess) {
				fmt.Println("access reason:", errAccess.Error())
			}
			fmt.Println("error closing writeCloser ", err)
			return err
		}
		objectParameters.Id = payloadWriter.ID().String()
	}

	fmt.Println("reached end of file, ", objectParameters.Id)
	localObject := Object{
		ParentID: p.ParentID(),
		Id:       payloadWriter.ID().String(), //fixme - find out how objectParameters.ID is the old ID....
	}
	fmt.Println("local", localObject)
	if err := objectParameters.ObjectEmitter.Emit(ctx, emitter.ObjectAddUpdate, localObject); err != nil {
		fmt.Println("could not emit add update ", err)
	}
	fmt.Println("notifying now")

	actionChan <- o.Notification(
		"upload complete!",
		"object "+objectParameters.Id+" completed", //we gleaned the ID during the write initiator.
		notification.Success,
		notification.ActionToast)
	fmt.Println("returning now")
	return nil
}

type Object struct {
	ParentID    string            `json:"parentID"`
	Name        string            `json:"name"`
	Id          string            `json:"id"`
	ContentType string            `json:"contentType"`
	Attributes  map[string]string `json:"attributes"`
	Size        uint64            `json:"size"`
	CreatedAt   int64             `json:"CreatedAt"`
}

type ObjectRange struct {
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
	Data   []byte `json:"data"`
}
