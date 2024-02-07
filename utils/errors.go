package utils

const (
	ErrorPendingInUse         string = "event already exists"
	ErrorNotFound             string = "event not found"
	ErrorNotPayload           string = "not of type payload"
	ErrorNotParameter         string = "not of type parameter"
	ErrorNotObject            string = "not of type object"
	ErrorNoSession            string = "no session available"
	ErrorNoToken              string = "no token available"
	ErrorNoSignature          string = "payload not signed correctly"
	ErrorNoDatabase           string = "no database available"
	ErrorTransacting          string = "error transacting"
	ErrorNoID                 string = "object has no id"
	ErrorNoNotification       string = "not a notification"
	ErrorWriterNotImplemented string = "containers cannot read data"
)
