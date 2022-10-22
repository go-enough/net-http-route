# Net HTTP Route
Simple http router based on Go's standard package `net/http`.

The route uses [ShiftPath](#shiftpath) technique.


## Why
Want to have a minimalist one-file feature rich web framework written in Go.


## Features
- use of standard Go interfaces;
- fast enough;
- minimalist;
- support of middlewares;
- support of dynamic parameters in a url path;
- one-file source code.


## Requirements
- Go 1.19.*, but the route can be used with other Go versions.


# License
BSD 2-Clause


## A complete example of use
```go
package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-enough/net-http-route/pkg/route"
)

const addr = ":8080"              // default address and port: 0.0.0.0:8080
const ttl = 10                    // seconds
const terminate = syscall.SIGTERM // OS says to terminate

func main() {
	log.Printf("source=%q msg=%q\n", "main", "hi")
	defer log.Printf("source=%q msg=%q\n", "main", "bye")

	// Listening to OS signals.
	ctx, shutdown := signal.NotifyContext(context.Background(), terminate)
	defer shutdown()

	// Creating a new route object and setting a default HTTP handler.
	app := route.New(http.NotFoundHandler())

	// Appplying two middlewares to the root: RequestId and NoTrailingSlash.
	// All the sub routes will be affected too.
	app.Use("/",
		route.RequestIdHandler(route.NewRUIDString),
		route.NoTrailingSlashHandler)

	// Adding a health endpoint and its handler to a route object.
	// If you use default settings try to run following commands:
	// `curl -v "http://127.0.0.1:8080/api/health"``
	// or
	// `curl -v "http://localhost:8080/api/health"`.
	app.AddFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		// This endpoint only responds to GET HTTP method.
		if !route.EnsureMethod(w, r, http.MethodGet) {
			log.Printf("source=%q method=%q error=%q\n",
				"/api/health",
				r.Method,
				route.ErrNotAllowed)

			return
		}

		// No time to explain.
		// Nothing to write.
		// Just saying we are up and running.
		w.WriteHeader(http.StatusNoContent)

		log.Printf("source=%q msg=%q\n", "/api/health", "ok")
	})

	// A web service is reachable at
	// http://localhost:8080
	// or
	// http://127.0.0.1:8080 .
	server := &http.Server{
		Addr:         addr,
		Handler:      app,
		ReadTimeout:  ttl * time.Second,
		WriteTimeout: ttl * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	// Starting serving HTTP requests.
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("source=%q error=%q\n", "server.ListenAndServe", err)
		}
	}()

	log.Printf("source=%q msg=%q\n", "main", "up and running")

	// Serving HTTP requests until shutting down.
	<-ctx.Done()

	log.Printf("source=%q msg=%q\n", "main", "shutting down")

	// Stopping listening to OS signals and cleaning up related resources asap.
	shutdown()

	// Waiting gracefully.
	grace, disgrace := context.WithTimeout(context.Background(), ttl*time.Second)
	defer disgrace()

	log.Printf("source=%q msg=%q\n", "main", "graceful shutdown")

	if err := server.Shutdown(grace); err != nil {
		log.Printf("source=%q msg=%q reason=%q\n",
			"main",
			"forced shutdown",
			err)
	}
}
```


## Plans, Notes, Todos
- [ ] More documentation, unit tests, benchmarks,
        examples will be added in the future;
- [ ] More info on used RFCs, standards,
        techniques will be added in the future;
- [ ] More middlewares and examples will be added in the future;
- [ ] To keep this repository thin as much as possible,
        middlewares and examples will live in dedicated repositories.

No big changes are planned in this repo,
only: bug fixes, very high important additions and changes.


## References
The route is influenced by

### ShiftPath
ShiftPath is a routing technique well described by Axel Wagner in an article
https://blog.merovius.de/posts/2017-06-18-how-not-to-use-an-http-router/ .
