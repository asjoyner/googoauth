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
	"encoding/json"
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

var (
	DeviceCodeURL    = "https://accounts.google.com/o/oauth2/device/code"
	TokenPollURL     = "https://www.googleapis.com/oauth2/v3/token"
	DeviceGrantType  = "http://oauth.net/grant_type/device/1.0"
	DeviceCodeScopes = map[string]struct{}{
		"profile": struct{}{},
		"openid":  struct{}{},
		"email":   struct{}{},
		"https://www.googleapis.com/auth/analytics":               struct{}{},
		"https://www.googleapis.com/auth/analytics.readonly":      struct{}{},
		"https://www.googleapis.com/auth/calendar":                struct{}{},
		"https://www.googleapis.com/auth/calendar.readonly":       struct{}{},
		"https://www.google.com/m8/feeds":                         struct{}{},
		"https://www.googleapis.com/auth/contacts.readonly":       struct{}{},
		"https://www.googleapis.com/auth/cloudprint":              struct{}{},
		"https://www.googleapis.com/auth/devstorage.full_control": struct{}{},
		"https://www.googleapis.com/auth/devstorage.read_write":   struct{}{},
		"https://www.googleapis.com/auth/fitness.activity.read":   struct{}{},
		"https://www.googleapis.com/auth/fitness.activity.write":  struct{}{},
		"https://www.googleapis.com/auth/fitness.body.read":       struct{}{},
		"https://www.googleapis.com/auth/fitness.body.write":      struct{}{},
		"https://www.googleapis.com/auth/fitness.location.read":   struct{}{},
		"https://www.googleapis.com/auth/fitness.location.write":  struct{}{},
		"https://www.googleapis.com/auth/fusiontables":            struct{}{},
		"https://www.googleapis.com/auth/youtube":                 struct{}{},
		"https://www.googleapis.com/auth/youtube.readonly":        struct{}{},
		"https://www.googleapis.com/auth/youtube.upload":          struct{}{},
		"https://www.googleapis.com/auth/drive.file":              struct{}{},
	}
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
		token = tokenFromGoogle(ctx, config)
		saveToken(cache, token)
	} else {
		// log.Printf("Using cached token %#v from %q", token, cache)
	}

	return config.Client(ctx, token)
}

// tokenFromGoogle chooses the easiest method for the user to acquire an OAuth
// token for the provided scope.
func tokenFromGoogle(ctx context.Context, config *oauth2.Config) *oauth2.Token {
	for _, scope := range config.Scopes {
		if _, ok := DeviceCodeScopes[scope]; !ok {
			return tokenFromWeb(ctx, config)
		}
	}
	return tokenFromConsole(ctx, config)
}

// tokenFromConsole uses the much easier flow for "Devices", but it only works
// for very limited scopes, named in DeviceCodeScopes.  For more details, see:
// https://developers.google.com/identity/protocols/OAuth2ForDevices#allowedscopes
func tokenFromConsole(ctx context.Context, config *oauth2.Config) *oauth2.Token {
	code, interval, err := getDeviceCode(config)
	if err != nil {
		log.Fatalf("Failed to get Device Code: %v", err)
	}

	token, err := pollOAuthConfirmation(config, code, interval)
	if err != nil {
		log.Fatalf("Failed to get authorization token: %v", err)
	}

	return token
}

// getDeviceCode follows the token acquisition steps outlined here:
// https://developers.google.com/identity/protocols/OAuth2ForDevices
func getDeviceCode(config *oauth2.Config) (string, int, error) {
	form := url.Values{
		"client_id": {config.ClientID},
		"scope":     {strings.Join(config.Scopes, " ")},
	}
	response, err := http.PostForm(DeviceCodeURL, form)
	if err != nil {
		return "", 0, err
	}

	var r struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	json.NewDecoder(response.Body).Decode(&r)

	fmt.Printf("Visit %s and enter this code. I'll wait for you.\n%s\n",
		r.VerificationURL, r.UserCode)

	return r.DeviceCode, r.Interval, nil
}

// pollOAuthConfirmation awaits a response token, as described here:
// https://developers.google.com/identity/protocols/OAuth2ForDevices
// deviceCode is the code presented to the user
// interval is the poll interval in seconds allowed by Google's OAuth servers.
func pollOAuthConfirmation(config *oauth2.Config, deviceCode string, interval int) (*oauth2.Token, error) {
	for {
		time.Sleep(time.Duration(interval) * time.Second)

		form := url.Values{
			"client_id":     {config.ClientID},
			"client_secret": {config.ClientSecret},
			"code":          {deviceCode},
			"grant_type":    {DeviceGrantType},
		}
		response, err := http.PostForm(TokenPollURL, form)
		if err != nil {
			return nil, err
		}

		var r struct {
			Error        string `json:"error"`
			AccessToken  string `json:"access_token"`
			ExpiresIn    int    `json:"expires_in"`
			RefreshToken string `json:"refresh_token"`
		}
		json.NewDecoder(response.Body).Decode(&r)

		switch r.Error {
		case "":
			return &oauth2.Token{RefreshToken: r.RefreshToken}, nil
		case "authorization_pending":
		case "slow_down":
			interval *= 2
		default:
			return nil, err
		}
	}

	panic("unreachable")
}

// tokenFromWeb works for all scopes, but requires the user to create a path
// for their webbrowser connect localhost to this process, or requires them to
// paste a URL that failed to load into the console where this process is
// running.  Both are a suboptimal user experience, IMHO.
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
