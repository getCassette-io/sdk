package main

import (
	"context"
	"fmt"
	"gitlab.com/NebulousLabs/go-upnp"
	"log"
	"net/http"
)

func expose(ctx context.Context, port uint16, desc string) (*upnp.IGD, error) {
	d, err := upnp.DiscoverCtx(ctx)
	if err != nil {
		return nil, err
	}
	// Discover external IP
	ip, err := d.ExternalIP()
	if err != nil {
		return nil, err
	}
	err = d.Forward(port, desc)
	if err != nil {
		return nil, err
	}
	fmt.Println("external ip is ", ip)
	return d, nil

}

func main() {
	ctx := context.Background()
	var port uint16 = 9001
	d, err := expose(ctx, port, "example application")
	if err != nil {
		log.Fatal("error ", err)
	}
	if ip, err := d.ExternalIP(); err != nil {
		log.Fatal("error ", err)
	} else {
		log.Println("external IP is ", ip)
	}
	if forwarded, err := d.IsForwardedTCP(port); err != nil {
		log.Fatal("error ", err)
	} else {
		log.Println(" forwarded ", forwarded)
	}

	// Start a simple web server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, you've reached my server!")
	})

	go func() {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
	}()

	fmt.Println("Started web server on http://localhost:9001")

	// Keep the application running
	select {}
	err = d.Clear(port)
	if err != nil {
		log.Fatal("error clearing ", err)
	}

}
