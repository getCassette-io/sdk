package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getCassette-io/sdk/database"
	"github.com/getCassette-io/sdk/emitter"
	"github.com/getCassette-io/sdk/utils"
	"log"
	"strconv"
	"sync"
	"time"
)

/*
for mocker we need an emitter
*/

type Generator func() string

type MockNotificationEvent struct {
	Name                      string
	DB                        database.Store
	network, walletId, bucket string
}

func NewMockNotificationEvent(name string, db database.Store) MockNotificationEvent {
	return MockNotificationEvent{
		Name: name,
		DB:   db,
	}
}
func (m MockNotificationEvent) Emit(c context.Context, _ emitter.EventMessage, p any) error {
	log.Println("emitting ", p)
	actualPayload, ok := p.(NewNotification)
	if !ok {
		return errors.New(utils.ErrorNoNotification)
	}
	log.Printf("%s firing notification %+v\r\n", m.Name, actualPayload)
	if m.DB == nil {
		return errors.New(utils.ErrorNoDatabase)
	}
	byt, err := json.Marshal(actualPayload)
	if err != nil {
		return err
	}
	if m.DB != nil {
		if err := m.DB.Create(database.NotificationBucket, actualPayload.Id, byt); err != nil {
			return err
		}
	}

	return nil
}

type NotificationType uint8

const (
	ActionNOOP NotificationType = iota
	ActionToast
	ActionNotification
	ActionClipboard
)
const (
	Success string = "success"
	Info           = "info"
	Warning        = "warning"
	Error          = "error"
	Spinner        = "spinner"
)

type Notifier interface {
	Notification(title, description, typz string, action NotificationType) NewNotification //creates a new notifier
	//GenerateIdentifier() string                                                            //generates an identifier fro the notification
	//SetContext(ctx context.Context)
	QueueNotification(notification NewNotification) //pushes a notification onto a sending queue
	ListenAndEmit()
	End() //listens for notifications and sends them out
}
type NewNotification struct {
	Id          string            `json:"id"`
	User        string            `json:"-"` //who is this message for so we can store it in the database
	Title       string            `json:"title"`
	Type        string            `json:"type"`
	Action      NotificationType  `json:"action"`
	Description string            `json:"description"`
	Meta        map[string]string `json:"meta"`
	CreatedAt   string            `json:"createdAt"`
	MarkRead    bool              `json:"markRead"`
}

type EmitNotifier struct { //used to emit messages over a provided emitter
	emitter.Emitter
}

type NotificationManager struct {
	emitter.Emitter
	DB             database.Store
	notificationCh chan NewNotification
	ctx            context.Context //to cancel the routine
	cancelFunc     context.CancelFunc
	wg             *sync.WaitGroup
	IDGenerator    Generator
}

func NewNotificationManager(wg *sync.WaitGroup, emit emitter.Emitter, ctx context.Context, generator Generator) NotificationManager {
	notificationCh := make(chan NewNotification) // Set bufferSize to a value greater than 0
	return NotificationManager{
		Emitter:        emit,
		notificationCh: notificationCh,
		ctx:            ctx,
		//cancelFunc:     cancelFunc,
		wg:          wg,
		IDGenerator: generator,
	}
}

//
//func (m *NotificationManager) SetContext(ctx context.Context) {
//	m.ctx = ctx
//}

func (m NotificationManager) End() {
	m.cancelFunc()
	defer close(m.notificationCh)
}
func (m NotificationManager) Notification(title, description, typez string, action NotificationType) NewNotification {
	identifier := m.IDGenerator()
	return NewNotification{
		Id:          identifier,
		Title:       title,
		Description: description,
		Type:        typez,
		Action:      action,
	}
}
func (m NotificationManager) QueueNotification(notification NewNotification) {
	notification.CreatedAt = strconv.FormatInt(time.Now().Unix(), 10)
	m.notificationCh <- notification
}

func (m NotificationManager) ListenAndEmit() {
	fmt.Println("ListenAndEmit routine started")
	m.wg.Add(1)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer func() {
			fmt.Println("Listener ending")
			m.wg.Done()
			ticker.Stop()
		}()

		for {
			select {
			case <-m.ctx.Done():
				return
			case not, ok := <-m.notificationCh:
				if !ok {
					fmt.Println("Notification channel closed, exiting ListenAndEmit")
					return
				}
				if err := m.Emit(m.ctx, emitter.NotificationAddMessage, not); err != nil {
					fmt.Println("Error in Emit: ", err)
					return
				}
				//a notification flag should decide whether this goes to the database

			case <-ticker.C:
				//fmt.Println("ListenAndEmit is still running")
			}
		}
	}()
}
