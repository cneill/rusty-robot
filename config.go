package main

import (
	//"flag"
	"github.com/williballenthin/govt"
)

type RustyConfig struct {
	Nick        string
	Host        string
	Port        int
	Channel     string
	LocalAddr   string
	Owner       string
	Password    string // SHA256
	CmdPrefix   string
	GooglAPIKey string
	VTAPIKey    string
	Ops         map[string]bool
	Mocking     map[string]bool
	Authed      map[string]bool
	VTClient    govt.Client
	SSL         bool
	Verbose     bool
}
