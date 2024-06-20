package object

import (
	"context"
	"crypto/ecdsa"
	"github.com/configwizard/sdk/config"
	"github.com/configwizard/sdk/payload"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"time"
)

// fixme - move this file out of object.
func ContainerBearerToken(p payload.Parameters, issuerKey keys.PublicKey, nodes []config.Peer) (bearer.Token, error) {
	var cnrID cid.ID
	if err := cnrID.DecodeString(p.ID()); err != nil {
		return bearer.Token{}, err
	}
	return ObjectBearerToken(cnrID, p, issuerKey, nodes)
}
func ObjectBearerToken(cnrID cid.ID, p payload.Parameters, issuerKey keys.PublicKey, nodes []config.Peer) (bearer.Token, error) {
	gA, err := p.ForUser()
	if err != nil {
		return bearer.Token{}, err
	}
	var gateSigner user.Signer = user.NewAutoIDSignerRFC6979(gA.PrivateKey().PrivateKey)
	var prmDial client.PrmDial
	prmDial.SetTimeout(30 * time.Second)
	prmDial.SetStreamTimeout(30 * time.Second)
	prmDial.SetContext(context.Background()) //do we need fine contorl over this with a timeout?
	sdkCli, err := p.Pool().RawClient()
	if err != nil {
		return bearer.Token{}, err
	}
	netInfo, err := sdkCli.NetworkInfo(context.Background(), client.PrmNetworkInfo{})
	if err != nil {
		return bearer.Token{}, err
	}
	var bearerToken bearer.Token
	bearerToken.ForUser(gateSigner.UserID())
	bearerToken.SetIat(netInfo.CurrentEpoch())
	bearerToken.SetNbf(netInfo.CurrentEpoch())
	bearerToken.SetExp(netInfo.CurrentEpoch() + p.Epoch()) // or particular exp value
	tab := eacl.Table{}
	tab.SetCID(cnrID)
	var records []*eacl.Record
	//allow
	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		record := eacl.NewRecord()
		record.SetOperation(op)
		record.SetAction(eacl.ActionAllow)
		equal := eacl.MatchStringEqual
		equal.DecodeString(cnrID.String())
		record.AddObjectContainerIDFilter(equal, cnrID)
		eacl.AddFormedTarget(record, eacl.RoleUnknown, gA.PrivateKey().PrivateKey.PublicKey)
		records = append(records, record)
	}
	//deny
	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		record := eacl.NewRecord()
		record.SetOperation(op)
		record.SetAction(eacl.ActionDeny)
		equal := eacl.MatchStringEqual
		equal.DecodeString(cnrID.String())
		record.AddObjectContainerIDFilter(equal, cnrID)

		eacl.AddFormedTarget(record, eacl.RoleOthers)
		records = append(records, record)
	}
	for _, r := range records {
		tab.AddRecord(r)
	}
	bearerToken.SetEACLTable(tab)
	var issuer user.ID
	issuer = user.ResolveFromECDSAPublicKey(ecdsa.PublicKey(issuerKey))
	bearerToken.SetIssuer(issuer)
	return bearerToken, nil
}
