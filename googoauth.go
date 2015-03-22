// googoauth is an oauth library for command-line tools
//
// It eases the process of connecting to Google Services via oauth, and storing
// credentials across invocations of a command line tool.
//
// It is closely based on the example code from the google-api-go-client, here:
// https://github.com/google/google-api-go-client/blob/master/examples/main.go

package googoauth

import (
	"encoding/gob"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Flags
var (
	debug    = flag.Bool("debug.http", false, "show HTTP traffic")
	authport = flag.String("authport", "12345", "HTTP Server port.  Only needed for the first run, your browser will send credentials here.  Must be accessible to your browser, and authorized in the developer console.")
)

// Client accepts the connection details, and makes an oAuth connection
//
// id and secret are the CLIENT ID and CLIENT SECRET which you can generate at
// the Google Developer Console: http://console.developers.google.com
// You want an "Installed Application" of type "Other".
//
// Scope defines the access you are requesting, it is specific to the application.
// Strings are URLs, eg. "https://www.googleapis.com/auth/calendar", typically
// accessed in Go via the constants in the Go API, eg.
// directory.AdminDirectoryGroupScope
func Client(id, secret string, scope []string) *http.Client {
	config := &oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		Scopes:       scope,
		Endpoint:     google.Endpoint,
	}

	ctx := context.Background()
	if *debug {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &logTransport{http.DefaultTransport},
		})
	}
	return newOAuthClient(ctx, config)
}

func osUserCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Caches")
	case "linux", "freebsd":
		return filepath.Join(os.Getenv("HOME"), ".cache")
	}
	log.Printf("TODO: osUserCacheDir on GOOS %q", runtime.GOOS)
	return "."
}

func tokenCacheFile(config *oauth2.Config) string {
	hash := fnv.New32a()
	hash.Write([]byte(config.ClientID))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(strings.Join(config.Scopes, " ")))
	fn := fmt.Sprintf("googoauth-tok%v", hash.Sum32())
	return filepath.Join(osUserCacheDir(), url.QueryEscape(fn))
}

func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := new(oauth2.Token)
	err = gob.NewDecoder(f).Decode(t)
	return t, err
}

func saveToken(file string, token *oauth2.Token) {
	f, err := os.Create(file)
	if err != nil {
		log.Printf("Warning: failed to cache oauth token: %v", err)
		return
	}
	defer f.Close()
	gob.NewEncoder(f).Encode(token)
}

func newOAuthClient(ctx context.Context, config *oauth2.Config) *http.Client {
	cache := tokenCacheFile(config)
	token, err := tokenFromFile(cache)
	if err != nil {
		token = tokenFromWeb(ctx, config)
		saveToken(cache, token)
	} else {
		// log.Printf("Using cached token %#v from %q", token, cache)
	}

	return config.Client(ctx, token)
}

// Only works for very limited scopes.  I haven't bothered to get it working.
// https://developers.google.com/accounts/docs/OAuth2ForDevices#allowedscopes
func tokenFromConsole(ctx context.Context, config *oauth2.Config) *oauth2.Token {
	url := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL to the authorize this application: %v\n", url)

	// Ask the user for the auth code
	var code string
	fmt.Printf("Paste the token you received: ")
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Failure reading response: %v", err)
	}

	// Exchange it for a token
	token, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Token exchange error: %v", err)
	}
	return token
}

func tokenFromWeb(ctx context.Context, config *oauth2.Config) *oauth2.Token {
	go http.ListenAndServe(fmt.Sprintf("localhost:%s", *authport), nil)
	ch := make(chan string)
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	http.HandleFunc("/auth", func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/favicon.ico" {
			http.Error(rw, "", 404)
			return
		}
		if req.FormValue("state") != randState {
			log.Printf("State doesn't match: req = %#v", req)
			http.Error(rw, "", 500)
			return
		}
		if code := req.FormValue("code"); code != "" {
			fmt.Fprintf(rw, "<h1>Success</h1>Authorized.")
			rw.(http.Flusher).Flush()
			ch <- code
			return
		}
		log.Printf("no code")
		http.Error(rw, "", 500)
	})

	config.RedirectURL = fmt.Sprintf("http://localhost:%s/auth", *authport)
	authURL := config.AuthCodeURL(randState)
	go openURL(authURL)
	log.Printf("Authorize this app at: %s", authURL)
	code := <-ch
	log.Printf("Got code: %s", code)

	token, err := config.Exchange(ctx, code)
	if err != nil {
		log.Fatalf("Token exchange error: %v", err)
	}
	return token
}

func openURL(url string) {
	try := []string{"xdg-open", "google-chrome", "open"}
	for _, bin := range try {
		err := exec.Command(bin, url).Run()
		if err == nil {
			return
		}
	}
	log.Printf("Error opening URL in browser.")
}
