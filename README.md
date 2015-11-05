# pySocks5Http
SOCKS5 server which connects via a HTTP proxy (prototype)
```
[APP] --(SOCKS5)--> [socks5http] ---> [HTTP Proxy] ---> [Internet]
```
This is prototype project to see if I could provide internet connectivity
to an application running behind a HTTP proxy, however the application
only has SOCK5 proxy support.

It works, however it is written in Python and performance/stability was
not one of my goals. I hope it helps.

## Usage
```
Usage: socks5http.py [options]

Options:
  -h, --help            show this help message and exit
  --bind=BIND           <ip:port> where service must listen
  --pac=PAC             <url | file> of Proxy Automatic Configuration
  --http-proxy=HTTP_PROXY
                        <host:port> of http proxy
  --direct              <host:port> of http proxy
```
