package main

import (
	// "bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	irc "github.com/fluffle/goirc/client"
	"github.com/fluffle/goirc/logging/glog"
	// "os"
	"strings"
)

var rc RustyConfig = RustyConfig{
	Host:      *flag.String("host", "asimov.freenode.net", "IRC server"),
	Channel:   *flag.String("channel", "#inventropy", "IRC channel"),
	Owner:     "bluffinpuffin",
	Password:  "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5",
	CmdPrefix: "!",
	Ops:       make(map[string]bool),
	Mocking:   make(map[string]bool),
	Authed:    make(map[string]bool),
}

type RustyConfig struct {
	Host      string
	Channel   string
	Owner     string
	Password  string // SHA256
	CmdPrefix string
	Ops       map[string]bool
	Mocking   map[string]bool
	Authed    map[string]bool
}

func handle_command(conn *irc.Conn, line *irc.Line, args []string) {
	command := args[0][len(rc.CmdPrefix):]
	args = args[1:]

	st := conn.StateTracker()
	authed := rc.Authed[line.Nick]

	if line.Nick == rc.Owner && authed {
		// Owner-only commands
		if command == "mock" {
			for _, n := range args {
				_, is_on := st.IsOn(rc.Channel, n)
				if is_on {
					rc.Mocking[n] = true
					conn.Privmsg(rc.Channel, "Now mocking "+n)
				}
			}
		} else if command == "unmock" {
			for _, n := range args {
				if rc.Mocking[n] {
					rc.Mocking[n] = false
					conn.Privmsg(rc.Channel, "No longer mocking "+n)
				}
			}
		}
	} else if (rc.Ops[line.Nick] || line.Nick == rc.Owner) && authed {
		// Ops-level commands
		if command == "poop" {
			conn.Privmsg(rc.Channel, "poop")
		}
	}
}

// Handle privmsgs
func handle_privmsg(conn *irc.Conn, line *irc.Line) {
	text := line.Text()
	args := strings.Split(text, " ")

	// Handle auth
	if !line.Public() {
		if strings.Index(text, rc.CmdPrefix+"identify") == 0 && len(args) == 2 {
			fmt.Println("User " + line.Nick + " attempting to auth...")
			h := sha256.New()
			h.Write([]byte(args[1]))
			pwd_hash := hex.EncodeToString(h.Sum(nil))
			if (line.Nick == rc.Owner || rc.Ops[line.Nick]) && rc.Password == pwd_hash {
				fmt.Println("Auth succeeded for " + line.Nick)
				rc.Authed[line.Nick] = true
				conn.Privmsg(line.Nick, "You're authenticated now.")
			} else {
				fmt.Println("WARNING: Auth failed for " + line.Nick + "!")
				conn.Privmsg(line.Nick, "You fucked up.")
			}
		}
	} else {
		// send to handle_command if we see the prefix at beginning of line
		if strings.Index(text, rc.CmdPrefix) == 0 {
			handle_command(conn, line, args)
		}

		// Handle mocking
		if rc.Mocking[line.Nick] {
			conn.Privmsg(rc.Channel, "Hey, everybody! "+line.Nick+" said something!")
			conn.Privmsg(rc.Channel, line.Nick+": "+line.Text())
			conn.Privmsg(rc.Channel, "Great job, "+line.Nick+"! ╭(ᐛ)و")
		}
	}
}

func main() {
	flag.Parse()
	glog.Init()

	// create new IRC connection
	cfg := irc.NewConfig("rusty_robot")
	cfg.SSL = true

	// dat SSL config
	cfg.SSLConfig = &tls.Config{
		MinVersion:         0,
		MaxVersion:         0,
		InsecureSkipVerify: false,
		ServerName:         "asimov.freenode.net",
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	cfg.Server = "asimov.freenode.net:6697"
	cfg.NewNick = func(n string) string { return n + "4" }
	c := irc.Client(cfg)
	c.EnableStateTracking()
	c.HandleFunc("connected",
		func(conn *irc.Conn, line *irc.Line) { conn.Join(rc.Channel) })

	// Set up a handler to notify of disconnect events.
	quit := make(chan bool)
	c.HandleFunc("disconnected",
		func(conn *irc.Conn, line *irc.Line) { quit <- true })

	c.HandleFunc(irc.PRIVMSG, handle_privmsg)

	reallyquit := false
	for !reallyquit {
		// connect to server
		if err := c.ConnectTo(rc.Host); err != nil {
			fmt.Printf("Connection error: %s\n", err)
			return
		}

		// wait on quit channel
		<-quit
	}
}
