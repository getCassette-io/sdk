package payload

import (
	//"github.com/configwizard/sdk/notification"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"io"
)

type UUID string

// this could be a struct. Nothing here needs to be directly tested.
type Parameters interface {
	ParentID() string //container ID holder?
	ID() string       //object or container ID holder...
	ForUser() (*wallet.Account, error)
	Name() string
	//Attributes() []object.Attribute //need to be able to pass around anything that can be set on the object
	Operation() eacl.Operation
	Epoch() uint64
	Pool() *pool.Pool
	io.ReadWriter //for data transfer pass an interface for a reader and writer. The use then will have the correct type (e.g put or get)
}

type Payload struct {
	OutgoingData []byte     `json:"data"` //data that will go out of band
	Signature    *Signature `json:"signature"`
	Uid          UUID       `json:"uid"`
	Complete     bool       `json:"-"`
	ResponseCh   chan bool  `json:"-"` // Channel to notify when the payload is signed
	Pool         *pool.Pool `json:"-"`
	MetaData     []byte     `json:"metadata"` //anything that we want to store temporarily (like a raw tranasction)
}

type Signature struct {
	HexSignature string `json:"hexSignature"` //the signature of the payload (otherwise called .data)
	HexSalt      string `json:"hexSalt"`      //the salt used
	HexPublicKey string `json:"hexPublicKey"` //the public key of the signer
	HexMessage   string `json:"hexMessage"`   //the actual signed data
}

func NewPayload(data []byte) Payload {
	return Payload{
		OutgoingData: data,
		Uid:          UUID(uuid.New().String()),
		ResponseCh:   make(chan bool),
	}
}
