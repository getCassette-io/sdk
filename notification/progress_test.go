package notification

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/getCassette-io/sdk/readwriter"
	"github.com/getCassette-io/sdk/utils"
	"github.com/getCassette-io/sdk/waitgroup"
)

func TestProgressBar(t *testing.T) {
	statusCh := make(chan ProgressMessage)
	writer := new(bytes.Buffer)

	// Simulating data
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00}
	data = append(data, data...)
	data = append(data, data...)
	data = append(data, data...)
	data = append(data, data...)
	dataReader := bytes.NewReader(data)

	ctx, cancelFunc := context.WithCancel(context.Background())
	logger := utils.NewTestLogger(t)
	wg := waitgroup.NewWaitGroup(logger)

	wp := NewDataProgressHandler(ctx, statusCh, writer, "test transfer", 50*time.Millisecond, logger)
	startProgressHandlerMessage := "start_progress_handler_" + utils.GetCurrentFunctionName()
	wg.Add(1, startProgressHandlerMessage)
	go func() {
		defer wg.Done(startProgressHandlerMessage)
		wp.Start(wg, ctx, int64(len(data)))
	}()

	startPrintingMessage := "start_printing" + utils.GetCurrentFunctionName()
	wg.Add(1, startPrintingMessage)
	go func() {
		defer wg.Done(startPrintingMessage)
		for {
			select {
			case status, ok := <-statusCh:
				if !ok {
					t.Log("status channel closed — exiting")
					return
				}
				t.Logf("Progress: %d%%, Written: %d bytes\n", status.Progress, status.BytesWritten)
			case <-ctx.Done():
				t.Log("finished")
				return
			}
		}
	}()
	// Simulate data transfer
	buf := make([]byte, 8)
	for {
		n, err := dataReader.Read(buf)
		if n > 0 {
			if _, err := wp.Write(buf[:n]); err != nil {
				t.Fatalf("error writing to buffer: %s", err)
			}
		}
		if err != nil {
			cancelFunc()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Finalize the progress bar
	wp.Finish()

	wg.Wait()

	// Test validation: Ensure written data matches expected data
	if writer.String() != string(data) {
		t.Errorf("written data does not match expected data. Got: %s, Want: %s", writer.String(), string(data))
	}
}

func TestProgressBarWithManager(t *testing.T) {
	mockProgressEmitter := MockProgressEvent{}
	manager := NewProgressHandlerManager(DataProgressHandlerFactory, mockProgressEmitter)
	writers := make([]*bytes.Buffer, 2) // Assume two progress bars for the test

	ctx, cancel := context.WithCancel(context.Background())
	logger := utils.NewTestLogger(t)

	wg := waitgroup.NewWaitGroup(logger)

	// Creating and starting multiple progress bars
	startProgressHandlerManagerMessage := "start_progress_handler_manager" + utils.GetCurrentFunctionName()

	for i := range writers {
		writers[i] = new(bytes.Buffer)
		bar := manager.AddProgressHandler(wg, ctx, writers[i], fmt.Sprintf("TestBar%d", i), logger)
		data := []byte{0xFF, 0xD8, 0xFF, byte(i)} // Sample data for each bar
		dataReader := bytes.NewReader(data)

		wg.Add(1, startProgressHandlerManagerMessage+fmt.Sprintf("TestBar%d", i))

		go func(b *DataProgressHandler, dr *bytes.Reader) {
			defer wg.Done(startProgressHandlerManagerMessage + fmt.Sprintf("TestBar%d", i))
			manager.StartProgressHandler(wg, ctx, b.name, int64(len(data)))

			buf := make([]byte, 1)
			for {
				n, err := dr.Read(buf)
				if n > 0 {
					if _, err := b.Write(buf[:n]); err != nil {
						t.Errorf("error writing to buffer: %s", err)
						return
					}
				}
				if err != nil {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			bar.Finish()
		}(bar, dataReader)
	}
	cancel()

	// Wait for all progress bars to complete
	wg.Wait()
	// Test validation for each writer
	for i, writer := range writers {
		expectedData := []byte{0xFF, 0xD8, 0xFF, byte(i)}
		if len(writer.String()) == 0 || writer.String() != string(expectedData) {
			t.Errorf("writer %d: written data does not match expected data. Got: %s, Want: %s", i, writer.String(), string(expectedData))
		}
	}
}
func TestProgressManagerWithDualStream(t *testing.T) {

	type MockObjectParameter struct {
		io.ReadWriter
	}
	progressChan := make(chan ProgressMessage)
	mockProgressEmitter := NewUIProgressEvent("progress channel", progressChan)
	manager := NewProgressHandlerManager(DataProgressHandlerFactory, mockProgressEmitter)
	writers := make([]*bytes.Buffer, 2) // Assume two progress bars for the test

	ctx, cancel := context.WithCancel(context.Background())
	logger := utils.NewTestLogger(t)

	wg := waitgroup.NewWaitGroup(logger)

	// Sample data for each bar - make sure they are different
	sampleData := [][]byte{
		{0xFF, 0xD8, 0xFF, 0x00}, // Data for first bar
		{0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD}, // Data for second bar
	}
	startProgressHandlerManagerMessage := "start_progress_handler_manager" + utils.GetCurrentFunctionName()

	for i := range writers {
		writers[i] = new(bytes.Buffer)

		dataReader := bytes.NewReader(sampleData[i]) // Use distinct data for each bar

		progressBarName := fmt.Sprintf("TestBar%d", i)
		progressBar := manager.AddProgressHandler(wg, ctx, writers[i], progressBarName, logger)

		dualStream := readwriter.DualStream{
			Reader: dataReader,
			Writer: progressBar,
		}

		objParam := &MockObjectParameter{
			ReadWriter: &dualStream,
		}

		wg.Add(1, startProgressHandlerManagerMessage+progressBarName)

		go func(obj *MockObjectParameter, progressBarName string, dataSize int64) {
			defer wg.Done(startProgressHandlerManagerMessage + progressBarName)
			manager.StartProgressHandler(wg, ctx, progressBarName, dataSize)

			buf := make([]byte, 1)
			for {
				n, err := obj.Read(buf)
				if n > 0 {
					if _, err := obj.Write(buf[:n]); err != nil {
						t.Errorf("error writing to buffer: %s", err)
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						t.Errorf("error reading from buffer: %s", err)
					}
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
		}(objParam, progressBarName, int64(len(sampleData[i])))
	}

	cancel()
	// Wait for all progress bars to complete
	wg.Wait()

	// Test validation for each writer
	for i, writer := range writers {
		if writer.String() != string(sampleData[i]) {
			t.Errorf("writer %d: written data does not match expected data. Got: %s, Want: %s", i, writer.String(), string(sampleData[i]))
		}
	}
}
