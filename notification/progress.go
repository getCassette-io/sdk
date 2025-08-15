package notification

import (
	"context"
	"errors"
	"fmt"
	"github.com/getCassette-io/sdk/emitter"
	"github.com/getCassette-io/sdk/utils"
	"github.com/getCassette-io/sdk/waitgroup"
	"github.com/machinebox/progress"
	"io"
	"log"
	"time"
)

type UIProgressEvent struct {
	name         string
	progressChan chan ProgressMessage
}

func NewUIProgressEvent(name string, progressChan chan ProgressMessage) UIProgressEvent {
	return UIProgressEvent{
		name:         name,
		progressChan: progressChan,
	}
}
func (m UIProgressEvent) Emit(c context.Context, message emitter.EventMessage, p any) error {
	if pyld, ok := p.(ProgressMessage); ok {
		//fmt.Printf("UIProgress - Progress [%s]: %d%%, Written: %d bytes\n", pyld.Title, pyld.Progress, pyld.BytesWritten)
		fmt.Println("update from ", pyld.Title)
		m.progressChan <- ProgressMessage{Title: pyld.Title, Progress: pyld.Progress}

	} else {
		return errors.New(utils.ErrorNotPayload)
	}
	return nil
}

type ProgressDetail string

const (
	ProgressUploading   ProgressDetail = "uploading"
	ProgressDownloading ProgressDetail = "downloading"
	ProgressFinalising  ProgressDetail = "finalising"
)

type ProgressMessage struct {
	Key          string
	Title        string
	Progress     int
	BytesWritten int64
	Completed    bool
	Remaining    time.Duration
	ExpectedSize int64
	Show         bool
	Error        string
	Detail       ProgressDetail
}

type ProgressHandlerFactory func(ctx context.Context, w io.Writer, name string, logger *log.Logger) ProgressHandler

type ProgressHandlerManager struct {
	//ctx context.Context
	emitter.Emitter
	ProgressHandlers       map[string]ProgressHandler
	progressHandlerFactory ProgressHandlerFactory
	//UpdatesCh              chan ProgressMessage // A channel to send updates back to the caller
	//activeBars     int
	//activeBarsLock sync.Mutex
}

func NewProgressHandlerManager(factory ProgressHandlerFactory, emitter emitter.Emitter) *ProgressHandlerManager {
	return &ProgressHandlerManager{
		//ctx:                    context.Background(),
		Emitter:                emitter,
		ProgressHandlers:       make(map[string]ProgressHandler),
		progressHandlerFactory: factory,
		//UpdatesCh:              make(chan ProgressMessage),
	}
}

func (p *ProgressHandlerManager) AddProgressHandler(wg *waitgroup.WG, ctx context.Context, w io.Writer, name string, logger *log.Logger) *DataProgressHandler {
	progressHandler, ok := p.progressHandlerFactory(ctx, w, name, logger).(*DataProgressHandler) // Corrected type assertion
	if !ok {
		panic("ProgressHandlerFactory did not return a *writerProgressBar")
	}

	p.ProgressHandlers[name] = progressHandler

	wgMessage := "Add_progress_handler" + utils.GetCurrentFunctionName()
	// Start listening to updates from this progress bar
	logger.Println("1. Add Progress Writer routine started")
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			delete(p.ProgressHandlers, name)
			//close(progressHandler.statusCh)
			logger.Println("1. ending writer routine")
		}()
		for {
			select {
			case <-ctx.Done(): //todo - no worker group here?

				logger.Println("1. Add Progress Writer routine stopped")
				//delete(p.ProgressHandlers, name)
				return
			case update, ok := <-progressHandler.statusCh:
				fmt.Println("received ")
				if !ok {
					logger.Println("1. statusCh closed, stopping Add Progress Writer routine")
					//delete(p.ProgressHandlers, name)
					return
				}
				err := p.Emit(ctx, emitter.ProgressMessage, update)
				if err != nil {
					logger.Println("error emitting ", err)
					return
				}
				if !update.Show {
					logger.Println("WE NEED finishing")
					close(progressHandler.statusCh)
					return
				}
			}
		}
	}()

	return progressHandler
}

func (p *ProgressHandlerManager) StartProgressHandler(wg *waitgroup.WG, ctx context.Context, name string, payloadSize int64) {
	if bar, ok := p.ProgressHandlers[name]; ok {
		if wBar, ok := bar.(*DataProgressHandler); ok {
			wBar.Start(wg, ctx, payloadSize)
		}
	}

}

type ProgressHandler interface {
	Start(wg *waitgroup.WG, ctx context.Context, payloadSize int64) // Initialize and start the progress bar
	Write(data []byte) (int, error)                                 // Update the progress bar to the current value
	Finish()                                                        // Finish the progress bar
}

type DataProgressHandler struct {
	logger *log.Logger
	*progress.Writer
	duration time.Duration
	name     string
	statusCh chan ProgressMessage
}

// this returns the interface
func DataProgressHandlerFactory(ctx context.Context, w io.Writer, name string, logger *log.Logger) ProgressHandler {
	statusCh := make(chan ProgressMessage) // Each bar should have its own channel
	writerProgressBar := NewDataProgressHandler(ctx, statusCh, w, name, 50*time.Millisecond, logger)
	return &writerProgressBar
}

// this returns an actual instance
func NewDataProgressHandler(ctx context.Context, statusCh chan ProgressMessage, rw io.Writer, name string, update time.Duration, logger *log.Logger) DataProgressHandler {
	w := DataProgressHandler{}
	w.logger = logger
	w.Writer = progress.NewWriter(rw)
	w.name = name
	w.duration = update
	w.statusCh = statusCh
	return w
}

func (w DataProgressHandler) Write(data []byte) (int, error) {
	return w.Writer.Write(data)
}

// Start is run on a routine so it can continously  update the channel
func (w DataProgressHandler) Start(wg *waitgroup.WG, ctx context.Context, payloadSize int64) {
	w.logger.Println("2. starting... ", w.name)
	// Implementation for Start
	status := ProgressMessage{
		Title: w.name,
		Show:  true,
	}
	w.logger.Println("2. Progress bar started ", w.name)
	progressChan := progress.NewTicker(ctx, w.Writer, payloadSize, w.duration)
	wgMessage := "start_handler_" + utils.GetCurrentFunctionName()
	wg.Add(1, wgMessage)
	go func() {
		defer func() {
			wg.Done(wgMessage)
			w.logger.Println(w.name, "\r\n2. Progress bar worker stopped")
		}()
		for {
			select {
			case <-ctx.Done():
				wg.Done(wgMessage)
				//fixme - never reached on cancellation
				//i think due to the fact the parent is called?
				fmt.Println("2. ending progress bar ", w.name)

				//errMsg, ok := ctx.Value("error").(string)
				//status := status
				//status.Title = w.name
				//if ok && errMsg != "" {
				//	//no error, finish gracefully?
				//	status.Error = errMsg
				//}
				//status.Show = false
				//w.statusCh <- status
				//wg.Done(wgMessage)
				return
			case p := <-progressChan:
				//send to a progress notifier that has been supplied
				if p.N() == 0 {
					fmt.Println("no data ")
					continue
				}
				fmt.Println("percent ", p.Percent())
				if p.Complete() {
					fmt.Println("COMPLETED")
					status := status
					status.Title = w.name + " completed"
					status.Show = false
					w.statusCh <- status
					return
				}
				status := status
				status.Title = w.name
				status.Progress = int(p.Percent())
				status.BytesWritten = p.N()
				status.ExpectedSize = p.Size()
				status.Remaining = p.Remaining().Round(250 * time.Millisecond)
				status.Show = true
				fmt.Printf("status %+v\r\n", status)
				w.statusCh <- status
			}
		}
		//////fixme: this can never end because the ctx cannot be cancelled
		//for p := range progressChan {
		//	if p.N() == 0 {
		//		w.logger.Println("no data")
		//		continue
		//	}
		//	if p.Complete() {
		//		w.logger.Println("progress bar completed. Exiting")
		//		return
		//	}
		//	status := status
		//	status.Title = w.name
		//	status.Progress = int(p.Percent())
		//	status.BytesWritten = p.N()
		//	status.ExpectedSize = p.Size()
		//	status.Remaining = p.Remaining().Round(250 * time.Millisecond)
		//	status.Show = true
		//	w.statusCh <- status
		//}
	}()
}

func (w DataProgressHandler) Update(current int64) {
	//obselete potentially
}
func (w DataProgressHandler) Finish() {
	// Implementation for Finish
	defer close(w.statusCh) // Close the statusCh channel

	err := w.Writer.Err()
	if err != nil {
		w.logger.Println("writer progress bar has an error ", err)
	}
}
