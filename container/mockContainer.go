package container

import (
	"context"
	"fmt"
	"github.com/configwizard/sdk/database"
	"github.com/configwizard/sdk/emitter"
	"github.com/configwizard/sdk/notification"
	object2 "github.com/configwizard/sdk/object"
	"github.com/configwizard/sdk/tokens"
	"github.com/configwizard/sdk/tui/views"
	"github.com/configwizard/sdk/waitgroup"
	"time"
)

type MockContainer struct {
	Id        string // Identifier for the object
	CreatedAt time.Time
	UpdatedAt time.Time
	ctx       context.Context
	// the data payload
	//the location its to be read from/saved to if necessary
	ContainerEmitter emitter.Emitter //todo - this needs to tell things its complete (async remember)
	notification.Notifier
	database.Store
}

func (o *MockContainer) SetNotifier(notifier notification.Notifier) {
	o.Notifier = notifier
}
func (o *MockContainer) SetStore(store database.Store) {
	o.Store = store
}
func (o *MockContainer) Create(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	//todo - create a new container
	return nil
}

func (o *MockContainer) Head(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	localContainer := Container{
		BasicACL:   0x1FBF9FFF,
		Name:       "Mock Container",
		Id:         p.Id,
		Attributes: make(map[string]string),
		CreatedAt:  time.Now(),
	}
	localContainer.Attributes["foo"] = "bar"
	//todo == this can use the same mechanism (ContainerAddUpdate) as it can supply a full object that just overwrites any existing entry.
	if err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, localContainer); err != nil {
		actionChan <- o.Notification(
			"failed to emit update",
			err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	actionChan <- o.Notification(
		"container head retrieved!",
		"container "+p.Id+" head retrieved",
		notification.Success,
		notification.ActionNotification)
	return nil
}

// List responds with all the IDs of containers owned by the public key.
func (o *MockContainer) List(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	listContainerContent := views.SimulateNeoFS(views.Containers, "") //search by container ID (
	//we need to now emit this list one at a time as we receive them (or as one array?)
	for _, v := range listContainerContent {
		fmt.Printf("emitting here %+v\r\n", v)
		err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, Container{Id: v.ID})
		if err != nil {
			fmt.Println("error listing new container ", p)
			actionChan <- o.Notification(
				"failed to list containers",
				"could not list containers "+err.Error(),
				notification.Error,
				notification.ActionNotification)
		}
		time.Sleep(100 * time.Millisecond)
	}
	actionChan <- o.Notification(
		"list complete!",
		"object "+o.Id+" completed",
		notification.Success,
		notification.ActionNotification)
	return nil
}

func (o *MockContainer) Delete(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	return nil
}
func (o *MockContainer) Read(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	// todo: list all containers
	wgMessage := "containerRead"
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			fmt.Println("[container] HEAD action completed")
		}()
		var exit bool
		for {
			select {
			case <-ctx.Done():
				fmt.Println("mock head exited")
				return
			default:
				retrieveObjects := views.SimulateNeoFS(views.List, p.Id) // Get the content based on the selected item
				for _, v := range retrieveObjects {
					err := p.ContainerEmitter.Emit(ctx, emitter.ContainerListUpdate, object2.Object{Id: v.ID, ParentID: p.Id, Name: v.Name, Size: uint64(v.Size), ContentType: "application/json", CreatedAt: time.Now().Unix()})
					if err != nil {
						fmt.Println("error reading new container ", err)
						actionChan <- o.Notification(
							"failed to list objects",
							"could not list objects "+err.Error(),
							notification.Error,
							notification.ActionNotification)
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
				exit = true
				break
			}
			if exit {
				actionChan <- o.Notification(
					"list complete!",
					"object "+o.Id+" completed",
					notification.Success,
					notification.ActionNotification)
				return
			}
		}
	}()

	return nil
}
