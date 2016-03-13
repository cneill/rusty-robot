package main

import (
	"crypto/tls"
	"encoding/json"
	//"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/codegangsta/cli"
	irc "github.com/fluffle/goirc/client"
	//"github.com/fluffle/goirc/logging/glog"
	"github.com/williballenthin/govt"
)

var CONFIG_FILE string
var RC RustyConfig

func ParseArgs(args []string) {
	app := cli.NewApp()
	app.Name = "rusty"
	app.Usage = "Ol' rusty"
	app.Version = "0.1a"
	app.Commands = []cli.Command{
		cli.Command{
			Name:   "run",
			Action: Connect,
			Usage:  "Run ol' Rusty!",
		},
	}
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config, C",
			Usage:       "location of your configuration file",
			Value:       GetConfigPath(),
			Destination: &CONFIG_FILE,
		},

		// IRC config
		cli.StringFlag{
			Name:  "host, H",
			Usage: "hostname of the IRC server",
			Value: "irc.freenode.net",
		},
		cli.IntFlag{
			Name:  "port, P",
			Usage: "port of the IRC server",
			Value: 6697,
		},
		cli.StringFlag{
			Name:  "channel, c",
			Usage: "channel to join",
			Value: "#inventropy",
		},
		cli.BoolTFlag{
			Name:  "insecure, N",
			Usage: "disable SSL",
		},

		// General
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
	}
	app.Before = func(c *cli.Context) error {
		LoadConfig(c)
		return nil
	}
	app.Run(args)
}

func GetConfigPath() string {
	return os.ExpandEnv("$HOME/.config/rusty-robot/rusty.rc")
}

func LoadConfig(ctx *cli.Context) {
	var contents []byte

	fmt.Printf("Loading config %s...\n", CONFIG_FILE)

	if _, err := os.Stat(CONFIG_FILE); err != nil {
		log.Fatalf("Unable to load config file!\n%s\n\n", CONFIG_FILE)
	}

	contents = handle_err(ioutil.ReadFile(CONFIG_FILE)).([]byte)
	err := json.Unmarshal(contents, &RC)
	if err != nil {
		log.Fatalf("%v\n", err)
	}

	// Override config file values with CLI options

	if &RC.Host == nil {
		RC.Host = ctx.String("host")
	}

	if &RC.Port == nil {
		RC.Port = ctx.Int("port")
	}

	if &RC.SSL == nil {
		RC.SSL = ctx.BoolT("insecure")
	}

	if &RC.Verbose == nil {
		RC.Verbose = ctx.Bool("verbose")
	}
}

func Connect(ctx *cli.Context) {
	fmt.Printf("Connecting to %s...\n", RC.Host)
	// create new IRC connection
	cfg := irc.NewConfig(RC.Nick, "rusty")
	cfg.SSL = RC.SSL

	if cfg.SSL {
		cfg.SSLConfig = &tls.Config{
			MinVersion:         0,
			MaxVersion:         0,
			InsecureSkipVerify: false,
			ServerName:         RC.Host,
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
	}
	cfg.Server = fmt.Sprintf("%s:%d", RC.Host, RC.Port)
	cfg.NewNick = func(n string) string { return n + "_" }
	c := irc.Client(cfg)
	c.EnableStateTracking()
	c.HandleFunc(irc.CONNECTED,
		func(conn *irc.Conn, line *irc.Line) {
			fmt.Printf("Connected to %s\n", RC.Host)
			conn.Join(RC.Channel)
		})

	// Set up a handler to notify of disconnect events.
	quit := make(chan bool)
	c.HandleFunc(irc.DISCONNECTED,
		func(conn *irc.Conn, line *irc.Line) { quit <- true })

	c.HandleFunc(irc.JOIN, func(conn *irc.Conn, line *irc.Line) {
		if line.Nick == conn.Config().Me.String() && line.Args[0] == RC.Channel {
			fmt.Printf("Joined channel %s\n", RC.Channel)
		}
	})

	c.HandleFunc(irc.PRIVMSG, handle_privmsg)

	reallyquit := false
	for !reallyquit {
		// connect to server
		if err := c.ConnectTo(RC.Host); err != nil {
			fmt.Printf("Connection error: %s\n", err)
			return
		}
		// wait on quit channel
		<-quit
	}

}

func main() {
	ParseArgs(os.Args)
	RC.VTClient = govt.Client{Apikey: RC.VTAPIKey, Url: "https://www.virustotal.com/vtapi/v2/"}
	RegisterHandlers()
}
