package container

import (
	"crypto/ecdsa"
	"github.com/google/uuid"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

func unsignedContainerSessionForOp(ownerSigner, gateSigner user.Signer, curEpoch uint64, op session.ContainerVerb) session.Container {
	var cnrSession session.Container
	cnrSession.SetIat(curEpoch)
	cnrSession.SetNbf(curEpoch)
	cnrSession.SetExp(curEpoch + 1000)
	cnrSession.SetID(uuid.New())
	cnrSession.SetIssuer(ownerSigner.UserID())
	cnrSession.SetAuthKey(gateSigner.Public())
	cnrSession.ForVerb(op)

	return cnrSession
}
func allowOpToOthers(eACL *eacl.Table, op eacl.Operation) {
	var rec eacl.Record
	rec.SetOperation(op)
	rec.SetAction(eacl.ActionAllow)
	eacl.AddFormedTarget(&rec, eacl.RoleOthers)

	eACL.AddRecord(&rec)
}
func denyOpToOthers(eACL *eacl.Table, op eacl.Operation) {
	var rec eacl.Record
	rec.SetOperation(op)
	rec.SetAction(eacl.ActionDeny)
	eacl.AddFormedTarget(&rec, eacl.RoleOthers)

	eACL.AddRecord(&rec)
}

func allowOpByPublicKey(eACL *eacl.Table, op eacl.Operation, pubKey ecdsa.PublicKey) {
	var rec eacl.Record
	rec.SetOperation(op)
	rec.SetAction(eacl.ActionAllow)
	eacl.AddFormedTarget(&rec, eacl.RoleUnknown, pubKey)

	eACL.AddRecord(&rec)
}
