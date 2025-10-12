package container

import (
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
func allowOpToOthers(op eacl.Operation) eacl.Record {
	target := eacl.NewTargetByRole(eacl.RoleOthers)
	record := eacl.ConstructRecord(eacl.ActionAllow, op, []eacl.Target{target})
	return record
}
func denyOpToOthers(op eacl.Operation) eacl.Record {
	target := eacl.NewTargetByRole(eacl.RoleOthers)
	record := eacl.ConstructRecord(eacl.ActionDeny, op, []eacl.Target{target})
	return record

	//var rec eacl.Record
	//rec.SetOperation(op)
	//rec.SetAction(eacl.ActionDeny)
	//eacl.AddFormedTarget(&rec, eacl.RoleOthers)

	//records = append(records, record)

	//eACL.AddRecord(&rec)
}

// func allowOpByPublicKey(eACL *eacl.Table, op eacl.Operation, userID user.ID) eacl.Record {
// 	//target := eacl.NewTargetByRole(eacl.RoleUnspecified)
// 	//record := eacl.ConstructRecord(eacl.ActionAllow, op, []eacl.Target{target})
// 	//return record

// 	var rec eacl.Record
// 	rec.SetOperation(op)
// 	rec.SetAction(eacl.ActionAllow)
// 	target := eacl.NewTargetByAccounts([]user.ID{userID})
// 	record := eacl.ConstructRecord(eacl.ActionDeny, op, []eacl.Target{target})
// 	return record
// 	//eacl.AddFormedTarget(&rec, eacl.RoleUnspecified, userID)

// 	//eACL.AddRecord(&rec)
// }
