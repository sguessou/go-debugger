package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"runtime"
	"strings"

	"sguessou/test-client/model"
)

var config = struct {
	appID               string
	appPassword         string
	authURL             string
	authURLMobile       string
	logout              string
	afterLogoutRedirect string
	authCodeCallback    string
	tokenEndpoint       string
}{
	appID:               "billingApp",
	authURL:             "http://localhost:8000/api/v1/login",
	authURLMobile:       "http://localhost:8000/api/v1/mobile_login",
	logout:              "",
	afterLogoutRedirect: "http://localhost:5000",
	authCodeCallback:    "http://localhost:5000/auth-code-redirect",
	tokenEndpoint:       "http://localhost:8000/api/v1/token_v2",
	appPassword:         "",
}

var t = template.Must(template.ParseFiles("template/index.html"))

// AppVar application private variables
type AppVar struct {
	AuthCode     string
	SessionState string
	State        string
	AccessToken  string
	Scope        string
	RefreshToken string
	Cookie       string
	Verifier     string
	Challenge    string
}

var appVar = AppVar{}

func main() {
	fmt.Println("Hello")
	http.HandleFunc("/", home)
	http.HandleFunc("/login-mobile", enabledLog(loginMobile))
	http.HandleFunc("/login", enabledLog(login))
	http.HandleFunc("/logout", enabledLog(logout))
	http.HandleFunc("/auth-code-redirect", enabledLog(authCodeRedirect))
	http.HandleFunc("/exchangeToken", enabledLog(exchangeToken))
	http.ListenAndServe(":5000", nil)
}

func enabledLog(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		handlerName := runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name()
		log.Println("--> " + handlerName)
		handler(w, r)
		log.Println("--> " + handlerName)
	}
}

func home(w http.ResponseWriter, r *http.Request) {

	t.Execute(w, appVar)
}

func login(w http.ResponseWriter, r *http.Request) {

	appVar.Verifier = ""
	appVar.Challenge = ""

	// create a redirect URL for authentication endpoint
	req, err := http.NewRequest("GET", config.authURL, nil)
	if err != nil {
		log.Print(err)
		return
	}

	cookie := r.Header.Get("Cookie")
	appVar.Cookie = cookie

	qs := url.Values{}
	qs.Add("redirect", "true")
	qs.Add("redirect_uri", config.authCodeCallback)

	req.URL.RawQuery = qs.Encode()
	http.Redirect(w, r, req.URL.String(), http.StatusFound)
}

func loginMobile(w http.ResponseWriter, r *http.Request) {
	// PKCE
	verifier, _ := verifier()
	appVar.Verifier = verifier.Value
	appVar.Challenge = verifier.CodeChallengeS256()

	// create a redirect URL for authentication endpoint
	req, err := http.NewRequest("GET", config.authURLMobile, nil)
	if err != nil {
		log.Print(err)
		return
	}

	cookie := r.Header.Get("Cookie")
	appVar.Cookie = cookie

	qs := url.Values{}
	qs.Add("redirect", "true")
	qs.Add("redirect_uri", config.authCodeCallback)
	qs.Add("code_challenge", appVar.Challenge)

	req.URL.RawQuery = qs.Encode()
	http.Redirect(w, r, req.URL.String(), http.StatusFound)
}

func authCodeRedirect(w http.ResponseWriter, r *http.Request) {
	appVar.AuthCode = r.URL.Query().Get("code")

	http.Redirect(w, r, "http://localhost:5000", http.StatusFound)
}

func logout(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	// q.Add("redirect_uri", "http://localhost:5000")
	q.Add("redirect_uri", config.afterLogoutRedirect)

	logoutURL, err := url.Parse(config.logout)
	if err != nil {
		log.Println(err)
		return
	}
	logoutURL.RawQuery = q.Encode()
	appVar = AppVar{}
	http.Redirect(w, r, logoutURL.String(), http.StatusFound)
}

// grant_type
//          REQUIRED.  Value MUST be set to "authorization_code".

//    code
//          REQUIRED.  The authorization code received from the
//          authorization server.

//    redirect_uri
//          REQUIRED, if the "redirect_uri" parameter was included in the
//          authorization request as described in Section 4.1.1, and their
//          values MUST be identical.

//    client_id
//          REQUIRED, if the client is not authenticating with the
//          authorization server as described in Section 3.2.1.

func exchangeToken(w http.ResponseWriter, r *http.Request) {
	cookie := r.Header.Get("Cookie")

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", appVar.AuthCode)
	form.Add("redirect_uri", config.authCodeCallback)

	if appVar.Verifier != "" {
		form.Add("code_verifier", appVar.Verifier)
	}

	req, err := http.NewRequest("POST", config.tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cookie", cookie)

	log.Println("@@@@@@@@@@@@ DEBUG REQ. HEADERS @@@@@@@@@@@@@@@@@@@")
	// Save a copy of this request for debugging.
	requestDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	if err != nil {
		log.Println(err)
		return
	}
	log.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")

	//req.SetBasicAuth(config.appID, config.appPassword)

	// Client
	c := http.Client{}
	res, err := c.Do(req)
	if err != nil {
		log.Println("Couldn't get access token", err)
		return
	}

	// Process response
	byteBody, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	if err != nil {
		log.Println(err)
		return
	}

	accessTokenResponse := &model.AccessTokenResponse{}
	json.Unmarshal(byteBody, accessTokenResponse)

	appVar.AccessToken = accessTokenResponse.AccessToken
	appVar.Scope = accessTokenResponse.Scope
	appVar.RefreshToken = accessTokenResponse.RefreshToken

	log.Println(string(byteBody))
	t.Execute(w, appVar)
}
