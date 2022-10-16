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
	"log"
	"net/http"

	"github.com/go-enough/net-http-route/pkg/route"
)

func main() {
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
		// This endpoint only responds on GET HTTP method.
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

	log.Printf("source=%q msg=%q\n", "main", "up and running")

	// A web service is reachable at
	// http://localhost:8080
	// or
	// http://127.0.0.1:8080 .
	err := http.ListenAndServe(":8080", app)
	if err != nil {
		log.Fatalf("source=%q err=%q\n", "main", err)
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
