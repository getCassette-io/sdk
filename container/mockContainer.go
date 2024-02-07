package container

import (
	"context"
	"fmt"
	"github.com/configwizard/sdk/database"
	"github.com/configwizard/sdk/emitter"
	"github.com/configwizard/sdk/notification"
	"github.com/configwizard/sdk/payload"
	"github.com/configwizard/sdk/tokens"
	"github.com/configwizard/sdk/tui/views"
	"github.com/configwizard/sdk/waitgroup"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/user"
	"log"
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

func (o *MockContainer) Create(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	//todo - create a new container
	return nil
}

func (o *MockContainer) Head(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	//todo - return the data about the container
	return nil
}

// List responds with all the IDs of containers owned by the public key.
func (o *MockContainer) List(wg *waitgroup.WG, ctx context.Context, p ContainerParameter, actionChan chan notification.NewNotification, token tokens.Token) error {
	userID := user.ResolveFromECDSAPublicKey(p.PublicKey)
	fmt.Println("user id is....", userID)
	lst := client.PrmContainerList{}
	lst.WithXHeaders() //fixme - dis
	fmt.Println("getting list with ", lst)
	r, err := p.Pl.ContainerList(ctx, userID, lst)
	if err != nil {
		actionChan <- o.Notification(
			"failed to list containers",
			"could not list containers "+err.Error(),
			notification.Error,
			notification.ActionNotification)
		return err
	}
	log.Printf("%v\r\n", r)
	//we need to now emit this list one at a time as we receive them (or as one array?)
	for _, v := range r {
		fmt.Printf("emitting here %+v\r\n", v)
		err := p.ContainerEmitter.Emit(ctx, emitter.ContainerAddUpdate, v.String())
		if err != nil {
			fmt.Println("error emitting new object ", p)
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
	//wgMessage := "containerList"
	//wg.Add(1, wgMessage)
	//go func() {
	//	defer func() {
	//		wg.Done(wgMessage)
	//		fmt.Println("[container] List action completed")
	//	}()
	//	fmt.Println("user id....", p.PublicKey)
	//	userID := user.ResolveFromECDSAPublicKey(p.PublicKey)
	//	fmt.Println("user id is....", userID)
	//	lst := client.PrmContainerList{}
	//	lst.WithXHeaders() //fixme - discover what this is for
	//	var exit bool
	//	for {
	//		select {
	//		case <-ctx.Done():
	//			fmt.Println("mock head exited")
	//			return
	//		default:
	//			fmt.Println("getting list with ", lst)
	//			r, err := p.Pl.ContainerList(ctx, userID, lst)
	//			if err != nil {
	//				actionChan <- o.Notification(
	//					"failed to list containers",
	//					"could not list containers "+err.Error(),
	//					notification.Error,
	//					notification.ActionNotification)
	//				return
	//			}
	//			log.Printf("%v\r\n", r)
	//			//we need to now emit this list one at a time as we receive them (or as one array?)
	//			for _, v := range r {
	//				fmt.Printf("emitting %+v\r\n", v)
	//				err := p.ContainerEmitter.Emit(p.ctx, emitter.ContainerListUpdate, v)
	//				if err != nil {
	//					fmt.Println("error emitting new object ", p)
	//					actionChan <- o.Notification(
	//						"failed to list containers",
	//						"could not list containers "+err.Error(),
	//						notification.Error,
	//						notification.ActionNotification)
	//				}
	//				time.Sleep(100 * time.Millisecond)
	//			}
	//			exit = true
	//			break
	//		}
	//		if exit {
	//			actionChan <- o.Notification(
	//				"list complete!",
	//				"object "+o.Id+" completed",
	//				notification.Success,
	//				notification.ActionNotification)
	//			return
	//		}
	//	}
	//}()
	return nil
}

func (o *MockContainer) Delete(p payload.Parameters, actionChan chan notification.NewNotification, token tokens.Token) (notification.NewNotification, error) {
	return notification.NewNotification{}, nil
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
				retrieveContainers := views.SimulateNeoFS(views.Containers, "") // Get the content based on the selected item
				for _, v := range retrieveContainers {
					err := p.ContainerEmitter.Emit(ctx, emitter.ContainerListUpdate, v)
					if err != nil {
						fmt.Println("error emitting new object ", p)
						actionChan <- o.Notification(
							"failed to list containers",
							"could not list containers "+err.Error(),
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
