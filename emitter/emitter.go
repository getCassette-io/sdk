package emitter

import (
	"context"
	"errors"
	"fmt"
	"github.com/configwizard/sdk/payload"
	"github.com/configwizard/sdk/utils"
)

type EventMessage string

const (
	SetAccount                EventMessage = "set_user_account"
	BalanceUpdate             EventMessage = "balance_update"
	BalanceError              EventMessage = "balance_error"
	RequestTransaction        EventMessage = "request_transaction"
	RequestDomainPurchase     EventMessage = "request_domain_purchase"
	RequestSign               EventMessage = "request_sign_payload"
	ResponseSign              EventMessage = "response_sign_payload"
	RequestAuthenticate       EventMessage = "request_authenticate"
	ContainerListUpdate       EventMessage = "container_list_update"
	ContainerRestrictUpdate   EventMessage = "container_restrict_update"
	ContainerAddUpdate        EventMessage = "container_add_update"
	HeadRetrieved             EventMessage = "head_retrieved" //used when not part of a larger asynchronous request
	ContainerRemoveUpdate     EventMessage = "container_remove_update"
	ObjectAddUpdate           EventMessage = "object_add_update"
	ObjectRangeUpdate         EventMessage = "object_range_update"
	ObjectRemoveUpdate        EventMessage = "object_remove_update"
	ObjectFailed              EventMessage = "object_failed"
	ContactAddUpdate          EventMessage = "contact_add_update"
	ContactRemoveUpdate       EventMessage = "contact_remote_update"
	NotificationAddMessage    EventMessage = "notification_add_message"
	NotificationRemoveMessage EventMessage = "notification_remove_message"
	ProgressMessage           EventMessage = "progress_message"
)

var AllEventMessages = []struct {
	Value  EventMessage
	TSName string
}{
	{SetAccount, "SetAccount"}, //some stuff around this to retrieve balances etc is necessary
	{BalanceUpdate, "BalanceUpdate"},
	{BalanceError, "BalanceError"},
	{RequestTransaction, "RequestTransaction"},
	{RequestDomainPurchase, "RequestDomainPurchase"},
	{RequestSign, "RequestSign"},
	{ResponseSign, "ResponseSign"},
	{RequestAuthenticate, "RequestAuthenticate"},
	{ContainerListUpdate, "ContainerListUpdate"},
	{ContainerAddUpdate, "ContainerAddUpdate"},
	{ContainerRestrictUpdate, "ContainerRestrictUpdate"},
	{HeadRetrieved, "HeadRetrieved"},
	{ContainerRemoveUpdate, "ContainerRemoveUpdate"},
	{ObjectAddUpdate, "ObjectAddUpdate"},
	{ObjectRangeUpdate, "ObjectRangeUpdate"},
	{ObjectRemoveUpdate, "ObjectRemoveUpdate"},
	{ObjectFailed, "ObjectFailed"},
	{ContactAddUpdate, "ContactAddUpdate"},
	{ContactRemoveUpdate, "ContactRemoveUpdate"},
	{NotificationAddMessage, "NotificationAddMessage"},
	{NotificationRemoveMessage, "NotificationRemoveMessage"},
	{ProgressMessage, "ProgressMessage"},
}

type Emitter interface {
	Emit(c context.Context, message EventMessage, payload any) error
}
type MockContainerEvent struct{}

func (e MockContainerEvent) Emit(c context.Context, message EventMessage, payload any) error {
	fmt.Printf("mock-emit - %s - %+v\r\n", message, payload)
	return nil
}

type MockObjectEvent struct{}

func (e MockObjectEvent) Emit(c context.Context, message EventMessage, payload any) error {
	fmt.Printf("mock-emit - %s - %+v\r\n", message, payload)
	return nil
}

type Signresponse func(signedPayload payload.Payload) error

type MockWalletConnectEmitter struct {
	Name         string
	SignResponse Signresponse //this is a hack while we mock. In reality the frontend calls this function
}

func (m MockWalletConnectEmitter) Emit(c context.Context, message EventMessage, p any) error {
	//fmt.Printf("%s emitting %s - %+v\r\n", m.Name, message, p)
	actualPayload, ok := p.(payload.Payload)
	if !ok {
		return errors.New(utils.ErrorNotPayload)
	}

	actualPayload.Signature = &payload.Signature{
		HexSignature: "8f523c87e447d49ca232b2724724a93204ed718ed884ad70a793eff191bab288c67cc52a558c486e838f4342346b9d44c72f09c1092d35eefa19157d03b6cd10",
		HexSalt:      "2343dd3334218b2c5292c4823cd15731",
		HexPublicKey: "031ad3c83a6b1cbab8e19df996405cb6e18151a14f7ecd76eb4f51901db1426f0b", //todo - should this come from the real wallet?
	}
	return m.SignResponse(actualPayload) //force an immediate signing of the payload
}

func (m MockWalletConnectEmitter) GenerateIdentifier() string {
	return "mock-signer-94d9a4c7-9999-4055-a549-f51383edfe57"
}

type MockRawWalletEmitter struct {
	Name         string
	SignResponse Signresponse //this is a hack while we mock. In reality the frontend calls this function
}

func (m MockRawWalletEmitter) Emit(c context.Context, message EventMessage, p any) error {
	fmt.Printf("%s emitting %s - %+v\r\n", m.Name, message, p)
	actualPayload, ok := p.(payload.Payload)
	if !ok {
		return errors.New(utils.ErrorNotPayload)
	}

	//the mock raw wallet emitter assumes that the signature will come from the wallet signing
	return m.SignResponse(actualPayload) //force an immediate signing of the payload
}

func (m MockRawWalletEmitter) GenerateIdentifier() string {
	return "mock-signer-94d9a4c7-9999-4055-a549-f51383edfe57"
}
