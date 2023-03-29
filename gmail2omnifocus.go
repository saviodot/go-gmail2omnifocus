package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"text/template"
	"time"

	"context"
	"google.golang.org/api/option"

	"golang.org/x/oauth2"
	"google.golang.org/api/gmail/v1"
	// gmail "google.golang.org/api/storage/v1"
)

type config struct {
	Address  string `json:"address"`
	ClientId string `json:"clientId"`
	Secret   string `json:"secret"`
}

var (
	authUrl  = "https://accounts.google.com/o/oauth2/auth"
	// tokenUrl = "https://accounts.google.com/o/oauth2/token"
	tokenUrl = "https://oauth2.googleapis.com/token"
	// redirectURL = "https://oauth-redirect.googleusercontent.com/r/omnifocus-plugin-382008"
	redirectURL = "https://oauth-redirect-sandbox.googleusercontent.com/r/omnifocus-plugin-382008"
	scope    = gmail.MailGoogleComScope

	mailTemplate = template.Must(template.New("task").Parse(`From: {{.From}}
To: {{.To}}
Subject: {{.Subject}}
Content-Type: text/plain; charset=UTF-8

{{.Body}}
`))
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gmail2omnifocus task\r\n")
		os.Exit(2)
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	cacheFile := os.ExpandEnv("$HOME/.config/gmail2omnifocus/cache.json")
	gm, err := newGmailer(cfg.ClientId, cfg.Secret, cacheFile)
	if err != nil {
		log.Fatal(err)
	}

	task := flag.Arg(0)
	body := flag.Arg(1)
	//TODO use body?
	err = gm.send(cfg.Address, task, body)
	if err != nil {
		log.Fatal(err)
	}
}

func loadConfig() (*config, error) {
	f, err := os.Open(os.ExpandEnv("$HOME/.config/gmail2omnifocus/config.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg config
	err = json.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

type gmailer struct {
	service *gmail.Service
}

type message struct {
	From    string
	To      string
	Subject string
	Body    string
}

func newGmailer(clientId, secret, cacheFile string) (*gmailer, error) {
	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: secret,
		Scopes:        []string{scope},
		RedirectURL: redirectURL,
 		Endpoint: oauth2.Endpoint{
 			AuthURL: authUrl,
 			TokenURL: tokenUrl,
 		},
	}
	ctx := context.Background()
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := config.AuthCodeURL("status", oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL for the auth dialog: %v\nPlease enter Code: ", url)

	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token. The HTTP Client returned by
	// conf.Client will refresh the token as necessary.
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}
	// fmt.Printf("Code: %v\n", code)
	// Use the custom HTTP client when requesting a token.
	// httpClient := &http.Client{Timeout: 2 * time.Second}
	// ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	token, err := config.Exchange(ctx, code)
	fmt.Printf("Token: %v\n", token)
	if err != nil {
		log.Fatal(err)
	}

	client := config.Client(ctx, token)
	client.Get("...")
	svc, err := gmail.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
	if err != nil {
		log.Fatal(err)
	}
	// client, err := auth(config)
	// if err != nil {
	// 	return nil, err
	// }
	// svc, err := gmail.New(client)
	// if err != nil {
	// 	return nil, err
	// }
	return &gmailer{
		service: svc,
	}, nil
}

func (g *gmailer) send(to, subject, body string) error {
	from := "me"

	mail := new(bytes.Buffer)

	mailTemplate.Execute(mail, message{
		From:    from,
		To:      to,
		Subject: subject,
		Body:    body,
		// Subject: encodeRFC2047(subject),
		// Body:    encodeRFC2047(body),
	})

	msg := gmail.Message{}
	msg.Raw = base64.URLEncoding.EncodeToString(mail.Bytes())

	_, err := g.service.Users.Messages.Send(from, &msg).Do()

	return err
}

func encodeRFC2047(str string) string {
	a := mail.Address{str, ""}
	return strings.Trim(a.String(), " <>")
}

func auth(config *oauth2.Config) (*http.Client, error) {
	//transport := &oauth2.Transport{
	//	// Source: google.ComputeTokenSource(""),
	//}
	// if _, err := config.TokenCache.Token(); err != nil {
	//	code := authWeb(config)
	//	if _, err := transport.Exchange(code); err != nil {
	//		return nil, err
	//	}
	//}
	//return transport.Client(), nil
	return nil, nil
}

func authWeb(config *oauth2.Config) string {
	ch := make(chan string)
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
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
	}))
	defer ts.Close()

	config.RedirectURL = ts.URL
	authUrl := config.AuthCodeURL(randState)
	go open(authUrl)
	log.Printf("Authorize this app at: %s", authUrl)
	code := <-ch
	return code
}

func open(url string) {
	commands := map[string]string{
		"darwin": "open",
		"linux":  "xdg-open",
	}
	if cmd, ok := commands[runtime.GOOS]; ok {
		exec.Command(cmd, url).Run()
	}
}
