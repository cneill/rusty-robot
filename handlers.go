package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	irc "github.com/fluffle/goirc/client"
	"github.com/williballenthin/govt"
	"golang.org/x/net/html"
)

var once sync.Once
var RustyScanner *UrlScanner

var VTHandler *VTUrlHandler
var TitleHandler *TitleUrlHandler
var ImgurHandler *ImgurUrlHandler

func GetScanner() *UrlScanner {
	once.Do(func() {
		RustyScanner = &UrlScanner{}
	})
	return RustyScanner
}

func RegisterHandlers() {
	s := GetScanner()

	VTHandler = &VTUrlHandler{
		Dangerous: make(map[string]bool),
		Safe:      make(map[string]bool),
	}
	s.Register(VTHandler)

	TitleHandler = &TitleUrlHandler{
		Cache:   make(map[string]string),
		Depends: &VTHandler.Safe,
	}
	s.Register(TitleHandler)

	ImgurHandler = &ImgurUrlHandler{
		UrlPattern: regexp.MustCompile(`https?://i.imgur.com/([a-zA-Z0-9]+)\.(jpg|jpeg|gif|gifv|png)`),
	}
	s.Register(ImgurHandler)
}

type UrlScanner struct {
	Handlers []UrlHandler
}

func (u *UrlScanner) Register(h UrlHandler) {
	u.Handlers = append(u.Handlers, h)
}

func (u *UrlScanner) Handle(conn *irc.Conn, line *irc.Line, url string) {
	for _, h := range u.Handlers {
		if h.CanHandle(url) {
			go h.Handle(conn, line, url)
		}
	}
}

type UrlHandler interface {
	CanHandle(url string) bool
	Handle(conn *irc.Conn, line *irc.Line, url string)
}

// VTUrlHandler searches VirusTotal's database for a given URL, and if it isn't
// found, submits it for scanning and polls for results
type VTUrlHandler struct {
	Safe      map[string]bool
	Dangerous map[string]bool
}

func (v *VTUrlHandler) CanHandle(url string) bool {
	return true
}

func (v *VTUrlHandler) Handle(conn *irc.Conn, line *irc.Line, url string) {
	r := v.GetVTReport(url)

	if r.Positives > 0 {
		v.Dangerous[url] = true
		conn.Privmsg(RC.Channel, "(」ﾟﾛﾟ)｣ ) WATCH OUT! VIRUSTOTAL SAYS "+url+" IS BAD NEWS!")
		conn.Privmsg(RC.Channel, "Permalink to scan results: "+r.Permalink)
	} else if r.Total == 0 {
		RC.VTClient.ScanUrl(url)
		time.AfterFunc(time.Second*45, func() {
			v.Handle(conn, line, url)
		})
	} else {
		v.Safe[url] = true
		if TitleHandler.CanHandle(url) {
			TitleHandler.Handle(conn, line, url)
		}
		//conn.Privmsg(RC.Channel, "( ͡° ͜ʖ ͡°) ) Me gusta...")
	}
}

func (v *VTUrlHandler) GetVTReport(url string) *govt.UrlReport {
	fmt.Printf("Searching for VirusTotal report on %s\n", url)
	return handle_err(RC.VTClient.GetUrlReport(url)).(*govt.UrlReport)
}

type TitleUrlHandler struct {
	Cache   map[string]string
	Depends *map[string]bool
}

func (t *TitleUrlHandler) CanHandle(url string) bool {
	dep := *t.Depends
	exclusions := regexp.MustCompile(`.*\.(jpg|jpeg|gif|png|json|mp4|ico|mp3|flv|txt|md)\z`)
	return dep[url] && !exclusions.MatchString(url)
}

func (t *TitleUrlHandler) Handle(conn *irc.Conn, line *irc.Line, url string) {
	var title string
	var ok bool
	fmt.Printf("Getting title for %s...\n", url)
	if title, ok = t.Cache[url]; !ok {
		resp := handle_err(http.Get(url)).(*http.Response)
		html_contents := handle_err(GetRespBody(*resp)).([]byte)
		mimetype := http.DetectContentType(html_contents)
		if strings.Index(mimetype, "text/html") == 0 {
			doc := handle_err(html.Parse(strings.NewReader(string(html_contents)))).(*html.Node)
			title = get_title(doc)
			if &title != nil {
				t.Cache[url] = title
			}
		} else {
			fmt.Printf("Unrecognized mimetype: %s\n", mimetype)
		}
	}
	if len(title) > 0 {
		conn.Privmsg(RC.Channel, "(づ｡◕‿‿◕｡)づ ) "+title)
	}
}

type ImgurUrlHandler struct {
	UrlPattern *regexp.Regexp
}

func (i *ImgurUrlHandler) CanHandle(url string) bool {
	if len(i.UrlPattern.FindString(url)) > 0 {
		return true
	}
	return false
}

func (i *ImgurUrlHandler) Handle(conn *irc.Conn, line *irc.Line, url string) {
	//var im Image
	parts := i.UrlPattern.FindStringSubmatch(url)
	id := parts[1]
	img_json_url := fmt.Sprintf("https://api.imgur.com/3/image/%s", id)
	/*
		fmt.Printf("API URL: %s\n", img_json_url)
		resp := handle_err(http.Get(img_json_url)).(*http.Response)
		body := handle_err(GetRespBody(*resp)).([]byte)
		fmt.Printf("Body:\n%s\n", body)
	*/
	body := i.GetImgData(img_json_url)
	fmt.Printf("%s", body)
	var im interface{}
	//err := json.Unmarshal(body, &im)
	err := json.Unmarshal(body, &im)
	if err != nil {
		log.Fatalf("%v", err)
	}

	r := im.(map[string]interface{})["data"].(map[string]interface{})
	for k, v := range r {
		if k == "title" && v != nil {
			conn.Privmsg(RC.Channel, "(づ｡◕‿‿◕｡)づ ) "+v.(string))
		}

		if k == "nsfw" && v.(bool) {
			conn.Privmsg(RC.Channel, "(」ﾟﾛﾟ)｣ ) WATCH OUT! IMGUR SAYS "+url+" IS NSFW!")
		}
	}
}

func (i *ImgurUrlHandler) GetImgData(url string) []byte {
	c := http.Client{}
	req := handle_err(http.NewRequest("GET", url, nil)).(*http.Request)
	req.Header.Add("Authorization", "Client-ID 903766e80c13ed6")
	resp := handle_err(c.Do(req)).(*http.Response)
	body := handle_err(GetRespBody(*resp)).([]byte)
	return body
}

func handle_command(conn *irc.Conn, line *irc.Line, args []string) {
	command := args[0][len(RC.CmdPrefix):]
	args = args[1:]

	st := conn.StateTracker()
	authed := RC.Authed[line.Nick]

	if line.Nick == RC.Owner && authed {
		// Owner-only commands
		if command == "mock" {
			for _, n := range args {
				_, is_on := st.IsOn(RC.Channel, n)
				if is_on {
					RC.Mocking[n] = true
					conn.Privmsg(RC.Channel, "Now mocking "+n)
				}
			}
		} else if command == "unmock" {
			for _, n := range args {
				if RC.Mocking[n] {
					RC.Mocking[n] = false
					conn.Privmsg(RC.Channel, "No longer mocking "+n)
				}
			}
		} else if command == "shorten" {
			fmt.Println("unimplemented")
		} else if command == "snoop" {
			fmt.Println("unimplemented")
		}
	} else if (RC.Ops[line.Nick] || line.Nick == RC.Owner) && authed {
		// Ops-level commands
		if command == "poop" {
			conn.Privmsg(RC.Channel, "poop")
		}
	} else if command == "identify" && !line.Public() {
		fmt.Println("User " + line.Nick + " attempting to auth...")
		h := sha256.New()
		h.Write([]byte(args[0]))
		pwd_hash := hex.EncodeToString(h.Sum(nil))
		if (line.Nick == RC.Owner || RC.Ops[line.Nick]) && RC.Password == pwd_hash {
			fmt.Println("Auth succeeded for " + line.Nick)
			RC.Authed[line.Nick] = true
			conn.Privmsg(line.Nick, "You're authenticated now.")
		} else {
			fmt.Println("WARNING: Auth failed for " + line.Nick + "!")
			conn.Privmsg(line.Nick, "You fucked up.")
		}
	}
}

func shorten_url(url string) {
	goog_url := "https://www.googleapis.com/urlshortener/v1/url"
	fmt.Printf("%s\n", goog_url)
}

// Handle privmsgs
func handle_privmsg(conn *irc.Conn, line *irc.Line) {
	text := line.Text()
	args := strings.Split(text, " ")
	//var url_regex = regexp.MustCompile(`\Ahttps?://([[:alnum:]][a-zA-Z0-9-]{1,61}[[:alnum:]]\.?){2,3}((%[0-9A-Fa-f]{2}|[-_.!~*';/?#:@&=+$,A-Za-z0-9])+)?\z`)
	var url_regex = regexp.MustCompile(`\b(([\w-]+://?|www[.])[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/)))`)

	// handle a prefixed command
	if strings.Index(text, RC.CmdPrefix) == 0 {
		handle_command(conn, line, args)
	} else if len(url_regex.FindString(text)) > 0 {
		s := GetScanner()
		s.Handle(conn, line, text)
	}
	// Handle mocking
	if RC.Mocking[line.Nick] {
		conn.Privmsg(RC.Channel, "Hey, everybody! "+line.Nick+" said something!")
		conn.Privmsg(RC.Channel, line.Nick+": "+line.Text())
		conn.Privmsg(RC.Channel, "Great job, "+line.Nick+"! ╭(ᐛ)و")
	}
}
