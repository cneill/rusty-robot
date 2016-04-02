package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	irc "github.com/fluffle/goirc/client"
	"golang.org/x/net/html"
)

func handle_err(obj interface{}, err error) interface{} {
	if err != nil {
		log.Fatalf("ERROR:\n%v", err)
	}
	return obj
}

func GetRespBody(resp http.Response) ([]byte, error) {
	//func get_html(resp http.Response) ([]byte, error) {
	contents, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return contents, err
}

func get_title(node *html.Node) string {
	var title string
	found := false
	if node.Type == html.ElementNode && node.Data == "title" {
		title = node.FirstChild.Data
		found = true
	}
	if !found {
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			res := get_title(c)
			if len(res) > 0 {
				title = res
			}
		}
	}
	return title
}

func SendMessage(conn *irc.Conn, msg string, handler UrlHandler) {
	if &handler != nil {
		conn.Privmsg(RC.Channel, fmt.Sprintf("[%s] %s", handler.Name(), msg))
	} else {
		conn.Privmsg(RC.Channel, msg)
	}
}
