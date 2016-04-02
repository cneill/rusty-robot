# Rusty Robot

╭(ᐛ)و WHEEEEEEEE ╭(ᐛ)و

## Setup

You'll need to edit the `rusty.rc.dist` file with your settings. To use the
VirusTotal URL handler, you'll need to [get an API key][vt].

When you've added your nick/server/etc., move `rusty.rc.dist` to
`~/.config/rusty-robot/rusty.rc`, OR supply the location of your config file
with the `-C` flag.

__Note:__ The Googl URL shortener is currently unimplemented, so you don't need
this API key (yet).

## Private Commands

- identify [password]

## Public Commands

- mock/unmock [list of nicks]
    - Makes fun of provided nicks (or stops)

## URL Handlers

Rusty will take certain actions when it sees different URLs, like:

- submits all links to VirusTotal for scanning and will alert if malware/etc. is
  detected
- grabs page titles for HTML pages (only if VirusTotal scan is clean)
- get imgur image titles, and warn if image is marked as NSFW

[vt]: https://www.virustotal.com/en/documentation/public-api
