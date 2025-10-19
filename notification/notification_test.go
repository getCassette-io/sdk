package notification

import (
	"context"
	"sync"
	"testing"
)

func TestNotification(t *testing.T) {
	context, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}

	m := NotificationManager{
		notificationCh: make(chan NewNotification),
		ctx:            context,
		wg:             &wg,
		cancelFunc:     cancel,
	}
	wg.Add(1)
	go m.ListenAndEmit()
	m.QueueNotification(NewNotification{
		Title:       "Success",
		Type:        "success",
		Action:      ActionNotification,
		Description: "Successful Notification",
	})
	m.cancelFunc()
	wg.Wait()
}
