package object

import (
	"context"
	"errors"
	"fmt"
	"github.com/bxcodec/faker/v3"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	oid "github.com/nspcc-dev/neofs-sdk-go/object/id"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/user"

	"github.com/cassette/sdk/database"
	"github.com/cassette/sdk/emitter"
	"github.com/cassette/sdk/notification"
	"github.com/cassette/sdk/payload"
	"github.com/cassette/sdk/tokens"
	"github.com/cassette/sdk/utils"
	"github.com/cassette/sdk/waitgroup"
	"io"
	"time"
)

type MockObject struct {
	Id, ContainerId string // Identifier for the object
	CreatedAt       time.Time
	UpdatedAt       time.Time
	// the data payload
	//the location its to be read from/saved to if necessary
	ObjectEmitter emitter.Emitter //todo - this needs to tell things its complete (async remember)
	notification.Notifier
	database.Store
}

func (o *MockObject) SetNotifier(notifier notification.Notifier) {
	o.Notifier = notifier
}
func (o *MockObject) SetStore(store database.Store) {
	o.Store = store
}

func (o *MockObject) SynchronousObjectHead(ctx context.Context, cnrId cid.ID, objID oid.ID, signer user.Signer, pl *pool.Pool) (Object, error) {
	return Object{}, nil
}
func (o *MockObject) SearchHeadByAttribute(ctx context.Context, cnrID cid.ID, attr object.Attribute, signer user.Signer, pl *pool.Pool) (Object, error) {
	return Object{}, nil
}

// todo - this will need to handle synchronous requests to the database and then asynchronous requests to the network
// basically load what we have but update it.
// these will need to fire notifications and events on completion.
// think about what to return here. We are trying to avoid anything being slow which means if we have something in the database
// we should return that with an 'synchronising' message. then the routine can update the UI for this request using an emitter
// and a message type with any new information?
// however maybe that isn;t the jjob of this and its the hob of the controller, who interfces with the UI. so this needs a chanenl to send messages on actually
func (o *MockObject) Head(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {

	mockObject := Object{
		ParentID:   p.ParentID(),
		Id:         p.ID(),
		Name:       fmt.Sprintf("%s.%s", faker.Word(), "txt"),
		Attributes: make(map[string]string),
		Size:       1025,
		CreatedAt:  time.Now().Unix(),
	}
	params, ok := p.(ObjectParameter)
	if !ok {
		err := params.ObjectEmitter.Emit(ctx, emitter.ObjectFailed, mockObject)
		if err != nil {
			return err
		}
	}

	return params.ObjectEmitter.Emit(ctx, emitter.ObjectAddUpdate, mockObject)
}
func (o *MockObject) Read(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	buffer := make([]byte, 10)
	wgMessage := "mock_read_" + utils.GetCurrentFunctionName()
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			fmt.Println("HEAD action completed")
		}()
		var exit bool
		for {
			select {
			case <-ctx.Done():
				fmt.Println("mock head exited")
				return
			default:
				n, err := p.Read(buffer)
				if n > 0 {
					if _, err := p.Write(buffer[:n]); err != nil {
						actionChan <- o.Notification(
							"failed to write to buffer",
							"could not write object to buffer "+err.Error(),
							notification.Error,
							notification.ActionNotification)
						return
					}
				}
				if err != nil {
					exit = true
					if err == io.EOF {
						fmt.Println("reached end of file")
						actionChan <- o.Notification(
							"download complete!",
							"object "+o.Id+" completed",
							notification.Success,
							notification.ActionNotification)
						break
					}
					fmt.Println("actual error ", err)
					actionChan <- o.Notification(
						"error",
						"no more data",
						notification.Error,
						notification.ActionNotification)
				}
				time.Sleep(2 * time.Millisecond)
			}
			if exit {
				break
			}
		}
	}()
	return nil
}
func (o *MockObject) Create(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	buffer := make([]byte, 10)
	wgMessage := "mock_write_" + utils.GetCurrentFunctionName()
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			fmt.Println("HEAD action completed")
		}()
		var exit bool
		for {
			select {
			case <-ctx.Done():
				fmt.Println("mock head exited")
				return
			default:
				n, err := p.Read(buffer)
				if n > 0 {
					if _, err := p.Write(buffer[:n]); err != nil {
						actionChan <- o.Notification(
							"failed to write to buffer",
							err.Error(),
							notification.Error,
							notification.ActionNotification)
						return
					}
				}
				if err != nil {
					if err == io.EOF {
						fmt.Println("reached end of file")
						break
					}
					fmt.Println("actual error ", err)
					actionChan <- o.Notification(
						"error",
						err.Error(),
						notification.Error,
						notification.ActionNotification)
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
			if exit {
				break
			}
		}
	}()
	return nil
}
func (o *MockObject) Delete(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	return nil
}
func (o *MockObject) List(wg *waitgroup.WG, ctx context.Context, p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) error {
	wgMessage := "mock_list_" + utils.GetCurrentFunctionName()

	params, ok := p.(*ObjectParameter)
	if !ok {
		return errors.New(utils.ErrorNotParameter)
	}
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			fmt.Println("HEAD action completed")
		}()
		var exit bool
		for {
			select {
			case <-ctx.Done():
				fmt.Println("mock head exited")
				return
			default:
				//emitting faker object
				//this is not representative of the object.go list method.
				err := params.ObjectEmitter.Emit(ctx, emitter.ObjectAddUpdate, p)
				if err != nil {
					fmt.Println("error emitting new object ", p)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			if exit {
				break
			}
		}
	}()
	return nil
}
