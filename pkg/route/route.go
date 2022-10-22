// Package route provides http routing based on ShiftPath technique.
//
// It allows to define routes in a one specific place.
package route

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	// HTTPSep is a standard url path separator "/" for HTTP.
	// It can be also used as a root path for your endpoints.
	HTTPSep = "/"
)

const (
	// HTTPHeaderContentType is a standard header name
	// "Content-Type" in canonical form.
	HTTPHeaderContentType = "Content-Type"

	// HTTPHeaderAllow ia a standard header name
	// "Allow" in canonical form.
	HTTPHeaderAllow = "Allow"
)

const (
	// HTTPHeaderRequestId is a custom header name
	// "Request-Id" in canonical form.
	HTTPHeaderRequestId = "Request-Id"
)

const (
	// HTTPContentTypeJSON is a standard content-type value
	// (MIME type) "application/json" for JSON content (documents).
	HTTPContentTypeJSON = "application/json"

	// HTTPContentTypeText is a standard content-type value
	// (MIME type) "text/plain" for text content (strings, documents).
	HTTPContentTypeText = "text/plain"
)

const (
	// dynamicParameterPrefix is a prefix ":"
	// to mark a dynamic parameter in a url path.
	dynamicParameterPrefix = ":"

	// dynamicParameterRoute is a generic name "*"
	// for routes with a dynamic parameter.
	dynamicParameterRoute = "*"
)

const (
	// itemListSep is a common separator "," for a list of values.
	itemListSep = ","
)

var (
	// ErrNotAllowed is a common error for not allowed HTTP methods.
	ErrNotAllowed = errors.New("not allowed")
)

// RUID is a random unique identifier.
type RUID [16]byte

// NilRUID is a nil value of RUID.
var NilRUID = RUID{}

// NewRUID creates a new RUID value.
// It takes data from Go's [crypto/rand] package.
// It might return NilRUID and an error
// when something goes wrong under the hood.
func NewRUID() (RUID, error) {
	r := RUID{}

	_, err := rand.Read(r[:])
	if err != nil {
		return NilRUID, err
	}

	return r, nil
}

// MustNewRUID creates a new RUID value.
// It takes data from Go's [crypto/rand] package.
// It panics when something goes wrong under the hood.
func MustNewRUID() RUID {
	r, err := NewRUID()
	if err != nil {
		panic(fmt.Sprintf("source=%q error=%q", "MustNewRUID", err))
	}

	return r
}

// NewUUID creates a new RUID value
// and makes it UUID version 4 (UUID4, UUIDv4) based on [RFC 4122].
// It takes data from Go's [crypto/rand] package.
// It might return NilRUID and an error
// when something goes wrong under the hood.
// More info about UUID: [RFC 4122].
//
// [RFC 4122]: https://www.ietf.org/rfc/rfc4122.txt
func NewUUID() (RUID, error) {
	r, err := NewRUID()
	if err != nil {
		return r, err
	}

	r[6] = (r[6] & 0x0f) | 0x40
	r[8] = (r[8] & 0x3f) | 0x80

	return r, nil
}

// MustNewUUID creates a new RUID value
// and makes it UUID version 4 (UUID4, UUIDv4).
// It takes data from Go's [crypto/rand] package.
// It panics when something goes wrong under the hood.
func MustNewUUID() RUID {
	r, err := NewUUID()
	if err != nil {
		panic(fmt.Sprintf("source=%q error=%q", "MustNewUUID", err))
	}

	return r
}

// String returns a HEX-style string representation of a RUID value.
func (r RUID) String() string {
	var b [32]byte

	hex.Encode(b[:], r[:])

	return string(b[:])
}

// UUIDString returns a HEX-style string representation of a RUID value
// that looks like UUID (GUID) string.
func (r RUID) UUIDString() string {
	var b [36]byte

	b[8], b[13], b[18], b[23] = '-', '-', '-', '-'

	hex.Encode(b[:8], r[:4])
	hex.Encode(b[9:13], r[4:6])
	hex.Encode(b[14:18], r[6:8])
	hex.Encode(b[19:23], r[8:10])
	hex.Encode(b[24:], r[10:])

	return string(b[:])
}

// NewRUIDString creates a new RUID
// and returns its common string representation as String() does.
// It panics when something goes wrong under the hood.
func NewRUIDString() string {
	r, err := NewRUID()
	if err != nil {
		panic(fmt.Sprintf("source=%q error=%q", "NewRUIDString", err))
	}

	return r.String()
}

// NewUUIDString creates a new RUID in UUID version 4 form
// and returns its common string representation as UUIDString() does.
// It panics when something goes wrong under the hood.
func NewUUIDString() string {
	r, err := NewUUID()
	if err != nil {
		panic(fmt.Sprintf("source=%q error=%q", "NewUUIDString", err))
	}

	return r.UUIDString()
}

// ShiftPath splits off the first component of v, which will be cleaned of
// relative components before processing.
// head will never contain a slash "/" and
// tail will always be a rooted path without trailing slash.
func ShiftPath(v string) (head, tail string) {
	v = path.Clean(HTTPSep + v)

	i := strings.Index(v[1:], HTTPSep) + 1
	if i == 0 {
		return v[1:], HTTPSep
	}

	return v[1:i], v[i:]
}

// middlewares is a simple collection of HTTP middlewares.
type middlewares []func(http.Handler) http.Handler

// wrap applies a collection of middlewares to a standard HTTP handler.
func (o middlewares) wrap(handler http.Handler) http.Handler {
	for i := len(o) - 1; i > -1; i-- {
		handler = o[i](handler)
	}

	return handler
}

// RequestIdHandler returns a simple HTTP middleware
// that adds "Request-Id" header into request and response objects.
// Parameter "rnd" is a function (generator) of unique string values.
// A user (developer) should take care of uniqueness of string values
// provided by the "rnd" function.
func RequestIdHandler(rnd func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := rnd()

			r.Header.Set(HTTPHeaderRequestId, id)
			w.Header().Set(HTTPHeaderRequestId, id)

			next.ServeHTTP(w, r)
		})
	}
}

// NoTrailingSlashHandler is a simple middleware
// that stops request processing
// if a url path of a request ends with trailing slash "/".
// It might be useful in some cases
// because the "ShiftPath" technique
// does not support (distinguish, favor) trailing slashes.
// A request fails with an HTTP 404 (not found) error.
func NoTrailingSlashHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin, err := url.Parse(r.RequestURI); origin.Path != HTTPSep &&
			strings.HasSuffix(origin.Path, HTTPSep) {
			http.NotFound(w, r)

			return
		} else if err != nil {
			Error(w, err, http.StatusInternalServerError)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// routeContextKey is a special dedicated type for context values
// used in the "Route" package according to Go's standard recommendations.
type routeContextKey string

// ContextGet gets a value from a standard Go's context.
func ContextGet(ctx context.Context, key string) any {
	return ctx.Value(routeContextKey(key))
}

// ContextSet puts a value into a standard Go's context.
func ContextSet(ctx context.Context, key string, value any) context.Context {
	return context.WithValue(ctx, routeContextKey(key), value)
}

// JSON writes JSON content and sets corresponding content type of a response.
func JSON(w http.ResponseWriter, data interface{}) (int, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}

	w.Header().Set(HTTPHeaderContentType, HTTPContentTypeJSON)

	return w.Write(bytes)
}

// Text writes plain text content
// and sets corresponding content type of a response.
func Text(w http.ResponseWriter, data string) (int, error) {
	w.Header().Set(HTTPHeaderContentType, HTTPContentTypeText)

	return w.Write([]byte(data))
}

// Error puts an error info and provided HTTP code into a response.
// It does not end a request, a user (developer) should do it by themselves.
// A user should not write to a response after calling this function.
func Error(w http.ResponseWriter, err error, code int) {
	http.Error(w, err.Error(), code)
}

// SetAllowedHTTPMethods sets allowed HTTP methods
// by using a standard "Allow" HTTP header.
func SetAllowedHTTPMethods(w http.ResponseWriter, methods ...string) {
	w.Header().Set(HTTPHeaderAllow, strings.Join(methods, itemListSep))
}

// EnsureMethod checks if an actual HTTP method of a request
// is equal to a desired one "method".
// It returns "true" if actual and desired methods
// are equal and "false" otherwise.
// If actual and desired methods are not equal
// then it also writes corresponding error info into a response,
// and in this case a user (developer) should stop processing a request.
func EnsureMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	return EnsureMethods(w, r, method, method)
}

// EnsureMethods does the same as EnsureMethod does,
// but puts a collection of allowed methods into a response
// if related checks fail.
func EnsureMethods(w http.ResponseWriter,
	r *http.Request,
	method string,
	methods ...string) bool {
	if method != r.Method {
		SetAllowedHTTPMethods(w, methods...)

		Error(w, ErrNotAllowed, http.StatusMethodNotAllowed)

		return false
	}

	return true
}

// Route represents a route provided by the ShiftPath.
//
// A complete example of use:
//
//	package main
//
//	import (
//		"context"
//		"log"
//		"net"
//		"net/http"
//		"os/signal"
//		"syscall"
//		"time"
//
//		"github.com/go-enough/net-http-route/pkg/route"
//	)
//
//	const addr = ":8080"              // default address and port: 0.0.0.0:8080
//	const ttl = 10                    // seconds
//	const terminate = syscall.SIGTERM // OS says to terminate
//
//	func main() {
//		log.Printf("source=%q msg=%q\n", "main", "hi")
//		defer log.Printf("source=%q msg=%q\n", "main", "bye")
//
//		// Listening to OS signals.
//		ctx, shutdown := signal.NotifyContext(context.Background(), terminate)
//		defer shutdown()
//
//		// Creating a new route object and setting a default HTTP handler.
//		app := route.New(http.NotFoundHandler())
//
//		// Appplying two middlewares to the root: RequestId and NoTrailingSlash.
//		// All the sub routes will be affected too.
//		app.Use("/",
//			route.RequestIdHandler(route.NewRUIDString),
//			route.NoTrailingSlashHandler)
//
//		// Adding a health endpoint and its handler to a route object.
//		// If you use default settings try to run following commands:
//		// `curl -v "http://127.0.0.1:8080/api/health"``
//		// or
//		// `curl -v "http://localhost:8080/api/health"`.
//		app.AddFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
//			// This endpoint only responds to GET HTTP method.
//			if !route.EnsureMethod(w, r, http.MethodGet) {
//				log.Printf("source=%q method=%q error=%q\n",
//					"/api/health",
//					r.Method,
//					route.ErrNotAllowed)
//
//				return
//			}
//
//			// No time to explain.
//			// Nothing to write.
//			// Just saying we are up and running.
//			w.WriteHeader(http.StatusNoContent)
//
//			log.Printf("source=%q msg=%q\n", "/api/health", "ok")
//		})
//
//		// A web service is reachable at
//		// http://localhost:8080
//		// or
//		// http://127.0.0.1:8080 .
//		server := &http.Server{
//			Addr:         addr,
//			Handler:      app,
//			ReadTimeout:  ttl * time.Second,
//			WriteTimeout: ttl * time.Second,
//			BaseContext: func(net.Listener) context.Context {
//				return ctx
//			},
//		}
//
//		// Starting serving HTTP requests.
//		go func() {
//			err := server.ListenAndServe()
//			if err != nil && err != http.ErrServerClosed {
//				log.Fatalf("source=%q error=%q\n", "server.ListenAndServe", err)
//			}
//		}()
//
//		log.Printf("source=%q msg=%q\n", "main", "up and running")
//
//		// Serving HTTP requests until shutting down.
//		<-ctx.Done()
//
//		log.Printf("source=%q msg=%q\n", "main", "shutting down")
//
//		// Stopping listening to OS signals and cleaning up related resources asap.
//		shutdown()
//
//		// Waiting gracefully.
//		grace, disgrace := context.WithTimeout(context.Background(),
//			ttl*time.Second)
//		defer disgrace()
//
//		log.Printf("source=%q msg=%q\n", "main", "graceful shutdown")
//
//		if err := server.Shutdown(grace); err != nil {
//			log.Printf("source=%q msg=%q reason=%q\n",
//				"main",
//				"forced shutdown",
//				err)
//		}
//	}
type Route struct {
	// a default (common, generic, failback, fallback, backup etc) HTTP handler
	http.Handler

	// a collection of sub routes
	routes map[string]http.Handler

	// a collection of middlewares
	middlewareHandlers middlewares

	// a dynamic parameter name when specified
	dynamicParameter string
}

// New constructs a new Route object.
func New(common http.Handler) *Route {
	return &Route{common, map[string]http.Handler{}, nil, ""}
}

// ServeHTTP implements "http.Handler" interface for Route
// and performs routing.
func (p *Route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	head := ""

	head, r.URL.Path = ShiftPath(r.URL.Path)

	action := p.routes[head]

	if action == nil && head != "" {
		if handler, ok := p.routes[dynamicParameterRoute]; ok {
			action = handler
			if route, ok := handler.(*Route); ok && route.param() != "" {
				r = r.WithContext(ContextSet(r.Context(), route.param(), head))
			}
		}
	}

	if action == nil {
		action = p.Handler
	}

	p.middlewares().wrap(action).ServeHTTP(w, r)
}

// Use adds a new one middleware or more
// into a list of middlewares for specific endpoint "path".
func (p *Route) Use(path string,
	middlewares ...func(http.Handler) http.Handler) *Route {
	head, tail := ShiftPath(path)

	head, _ = toDynParam(head)

	if head == "" {
		p.setMiddlewares(middlewares)
	} else {
		if route, ok := p.routes[head].(*Route); ok {
			route.Use(tail, middlewares...)
		} else {
			p.routes[head] = New(p.Handler).Use(tail, middlewares...)
		}
	}

	return p
}

// Add adds a pair of a new route (endpoint) "path" and its HTTP "handler"
// that can be resolved by Route.
func (p *Route) Add(path string, handler http.Handler) *Route {
	if handler == nil {
		return p
	}

	head, tail := ShiftPath(path)

	head, dynParam := toDynParam(head)

	if head == "" {
		p.routes[head] = handler
	} else {
		if route, ok := p.routes[head].(*Route); ok {
			route.Add(tail, handler)
		} else {
			p.routes[head] = New(p.Handler).
				Add(tail, handler).
				setParam(dynParam)
		}
	}

	return p
}

// AddFunc adds a pair of a new route (endpoint) "path" and its HTTP "handler"
// that can be resolved by Route.
// It allows to use
// a "func (http.ResponseWriter, *http.Request)" function (object)
// as a HTTP handler.
// Here anonymous function can be used as a HTTP handler.
func (p *Route) AddFunc(path string, f http.HandlerFunc) *Route {
	if f == nil {
		return p
	}

	return p.Add(path, f)
}

// middlewares is a simple getter for Route's middlewares property.
func (p *Route) middlewares() middlewares {
	return p.middlewareHandlers
}

// setMiddlewares is a simple setter for Route's middlewares property.
func (p *Route) setMiddlewares(v middlewares) *Route {
	p.middlewareHandlers = v

	return p
}

// param is a simple getter for Route's dynamic parameter property.
func (p *Route) param() string {
	return p.dynamicParameter
}

// setParam is a simple setter for Route's dynamic parameter property.
func (p *Route) setParam(v string) *Route {
	p.dynamicParameter = v

	return p
}

// toDynParam returns a pair of a dynamic parameter route "*" and its name
// if a path is a (has a) dynamic parameter specified.
// Unmodified path and no name are returned otherwise.
func toDynParam(v string) (head string, dynamicParameter string) {
	if strings.HasPrefix(v, dynamicParameterPrefix) {
		return dynamicParameterRoute, v[1:]
	}

	return v, ""
}
