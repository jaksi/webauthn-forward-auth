package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	domain     = flag.String("domain", "", "Domain")
	authDomain = flag.String("auth-domain", "", "Auth domain")
	configFile = flag.String("config", "config.json", "Config file")
)

type user struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *user) WebAuthnID() []byte {
	return u.ID
}

func (u *user) WebAuthnName() string {
	return u.Name
}

func (u *user) WebAuthnDisplayName() string {
	return u.Name
}

func (u *user) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func generateToken() []byte {
	b := make([]byte, 64)
	if n, err := rand.Read(b); err != nil || n != 64 {
		log.Fatalf("Failed to generate user ID, got %v bytes, error: %v", n, err)
	}
	return b
}

type session struct {
	user   string
	expiry time.Time
}

func main() {
	flag.Parse()
	if *domain == "" || *authDomain == "" {
		log.Fatalf("Domain and auth domain must be set")
	}

	loginTemplate, err := template.ParseFiles("login.html")
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	auth, err := webauthn.New(&webauthn.Config{
		RPDisplayName: *domain,
		RPID:          *domain,
		RPOrigins:     []string{fmt.Sprint("https://", *authDomain)},
	})
	if err != nil {
		log.Fatalf("Failed to initialize webauthn: %v", err)
	}

	var users []user
	b, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	if len(b) != 0 {
		if err := json.Unmarshal(b, &users); err != nil {
			log.Fatalf("Failed to unmarshal config: %v", err)
		}
	}

	sessions := make(map[string]session)

	var sessionData *webauthn.SessionData

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "register.html")
	})

	http.HandleFunc("/register/begin", func(w http.ResponseWriter, r *http.Request) {
		userName := r.URL.Query().Get("user")
		var u *user
		for i, _ := range users {
			if users[i].Name == userName {
				u = &users[i]
				break
			}
		}
		if u == nil {
			if userName == "" {
				log.Printf("Empty username")
				return
			}
			users = append(users, user{ID: generateToken(), Name: userName, Credentials: []webauthn.Credential{}})
			u = &users[len(users)-1]
			j, err := json.MarshalIndent(u, "", "  ")
			if err != nil {
				log.Fatalf("Failed to marshal: %v", err)
			}
			fmt.Println(string(j))
		}
		var options *protocol.CredentialCreation
		options, sessionData, err = auth.BeginRegistration(u)
		if err != nil {
			log.Printf("Failed to begin registration: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(options); err != nil {
			log.Printf("Failed to encode options: %v", err)
			return
		}
	})

	http.HandleFunc("/register/finish", func(w http.ResponseWriter, r *http.Request) {
		userName := r.URL.Query().Get("user")
		var u *user
		for i, _ := range users {
			if users[i].Name == userName {
				u = &users[i]
				break
			}
		}
		if u == nil {
			log.Print("No user")
			return
		}
		credential, err := auth.FinishRegistration(u, *sessionData, r)
		if err != nil {
			log.Printf("Failed to finish registration: %v", err)
			return
		}
		j, err := json.MarshalIndent(credential, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal: %v", err)
		}
		fmt.Println(string(j))
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Webauthn-Token")
		if err == nil {
			b, err := base64.StdEncoding.DecodeString(cookie.Value)
			if err == nil {
				token := string(b)
				s, ok := sessions[token]
				if ok {
					if time.Now().Before(s.expiry) {
						w.Header().Set("X-Webauthn-User", s.user)
						return
					}
					delete(sessions, token)
				}
			}
		}
		host := r.Header.Get("X-Forwarded-Host")
		uri := r.Header.Get("X-Forwarded-Uri")
		redirect := url.QueryEscape(fmt.Sprint(host, uri))
		http.Redirect(w, r, fmt.Sprintf("https://%v/login?redirect=%v", *authDomain, redirect), http.StatusFound)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect")
		if err := loginTemplate.Execute(w, redirect); err != nil {
			log.Fatalf("Failed to execute template: %v", err)
		}
	})

	http.HandleFunc("/login/begin", func(w http.ResponseWriter, r *http.Request) {
		var options *protocol.CredentialAssertion
		options, sessionData, err = auth.BeginDiscoverableLogin()
		if err != nil {
			log.Printf("Failed to begin login: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(options); err != nil {
			log.Printf("Failed to encode options: %v", err)
			return
		}
	})

	http.HandleFunc("/login/finish", func(w http.ResponseWriter, r *http.Request) {
		var u *user
		_, err := auth.FinishDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
			for i, _ := range users {
				if bytes.Equal(users[i].WebAuthnID(), userHandle) {
					u = &users[i]
					return u, nil
				}
			}
			return nil, errors.New("No user")
		}, *sessionData, r)
		if err != nil {
			log.Printf("Failed to finish login: %v", err)
			return
		}
		token := generateToken()
		sessions[string(token)] = session{u.Name, time.Now().Add(24 * time.Hour)}
		http.SetCookie(w, &http.Cookie{Name: "Webauthn-Token", Value: base64.StdEncoding.EncodeToString(token), Domain: *domain, Path: "/"})
	})

	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
