package object

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/getCassette-io/sdk/config"
	"github.com/getCassette-io/sdk/payload"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/user"
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
	var records []eacl.Record
	//allow
	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		// Create target for the specific user
		target := eacl.NewTargetByAccounts([]user.ID{gateSigner.UserID()})

		// Create container filter
		containerFilter := eacl.NewFilterObjectsFromContainer(cnrID)

		// Construct record with proper parameters
		record := eacl.ConstructRecord(eacl.ActionAllow, op, []eacl.Target{target}, containerFilter)
		records = append(records, record)
	}
	//deny
	for op := eacl.OperationGet; op <= eacl.OperationRangeHash; op++ {
		// Create target for others (all users except the specific user)
		target := eacl.NewTargetByRole(eacl.RoleOthers)

		// Create container filter
		containerFilter := eacl.NewFilterObjectsFromContainer(cnrID)

		// Construct record with proper parameters
		record := eacl.ConstructRecord(eacl.ActionDeny, op, []eacl.Target{target}, containerFilter)
		records = append(records, record)
	}
	tab.SetRecords(records)
	bearerToken.SetEACLTable(tab)
	var issuer user.ID
	issuer = user.NewFromECDSAPublicKey(ecdsa.PublicKey(issuerKey))
	bearerToken.ForUser(issuer)
	return bearerToken, nil
}
