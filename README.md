# OmniProxy
A TCP, UDP and SSL Proxy supporting SNI.

## Installing

```bash
>>> pip install pyOpenSSL
>>> pip install twisted
>>> ./omniproxy.py -h
usage: omniproxy.py [-h] [--local-port <port>] --destination <destination> [--listen-address <listen-address>]
                    [--tcp] [--udp] [--cafile <certificate-file>] [--log-folder LOG_FOLDER] [--quiet]

Modular Intercept Proxy

optional arguments:
  -h, --help            show this help message and exit
  --local-port <port>, -p <port>
                        Local proxy port (default:443)
  --destination <destination>, -d <destination>
                        Server Destination example www.google.com:80
  --listen-address <listen-address>, -l <listen-address>
                        Specify the listen address (default is 0.0.0.0)
  --tcp, -t
  --udp, -u
  --cafile <certificate-file>, -c <certificate-file>
  --log-folder LOG_FOLDER
  --quiet, -q
```

#### Converting Burp Certs

1. Export your Burp Certificate
  - Export with the **Certificate in DER format** option
2. Export your Burp Private key
  - Export with the **Private Key in DER format** option
3. Use the **./burp2omni.sh** script
  - This Converts both the Private Key and Certifate from the binary DER format to the base64 PEM format. Then merges them into a single file.

## SNI Proxy

When the Proxy recieves a SSL Connection. The first packet the of the **Client Hello Packet** contains the destination server. Using this information we can block anymore data transfer and query the Destination Server for their Certificate.

Once the Server has the paramaters for that certificate you can generate a new key certificate pair and sign it with a CA Cert. 

TLDR: This proxy waits until the connection tells the proxy where the origional destination is. Then it clones that servers Certificate and continues negotating the connection. 

This makes it possoble to have a single proxy on a single port and foward it to many destinations. 

**SNI Proxy Example:**
```bash
[gen0@gen0-test OmniProxy]$ sudo ./omniproxy.py -c ca.pem   --local-port 443 -d example.com:443
Getting Server Certificate from example.com:443
Cert already exists common_name=www.example.org
TCP[SSL] 0.0.0.0:443 -> example.com:443
#0: New Connection to destination <forwarder.SSLProxyServer object at 0x7f080ea639a0>
Getting Server Certificate from example.com:443
Cert already exists common_name=www.example.org
#0: New Connection on local server <forwarder.SSLProxyClient object at 0x7f080ea79460>
#1:C->S (75 bytes):
GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.74.0
Accept: */*


#1:C<-S (335 bytes):
HTTP/1.1 200 OK
Age: 534892
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Mon, 18 Jan 2021 19:57:15 GMT
Etag: "3147526947+ident"
Expires: Mon, 25 Jan 2021 19:57:15 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (nyb/1D1A)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1256


#1:C<-S (1256 bytes):
<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>

#1: Server closed connection
#1: Client closed connected
```

## TCP Proxy

**TCP Proxy Example:**
```bash
gen0@gen0-test OmniProxy]$ sudo ./omniproxy.py --local-port 80 --tcp -d example.com:80
TCP 0.0.0.0:80 -> example.com:80
#0: New Connection to destination <twisted.protocols.portforward.ProxyServer object at 0x7f467df20850>
#0: New Connection on local server <twisted.protocols.portforward.ProxyClient object at 0x7f467df20af0>
#1:C->S (75 bytes):
GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.74.0
Accept: */*


#1:C<-S (1591 bytes):
HTTP/1.1 200 OK
Age: 471203
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Mon, 18 Jan 2021 19:46:18 GMT
Etag: "3147526947+ident"
Expires: Mon, 25 Jan 2021 19:46:18 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (nyb/1D0C)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1256

<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>

#1: Server closed connection
#1: Client closed connected
```

## UDP Proxy


**UDP Proxy Example:**
```bash
[gen0@gen0-test OmniProxy]$ ./omniproxy.py --local-port 2222 --udp -d 1.1.1.1:53
UDP 0.0.0.0:2222 -> 1.1.1.1:53
#0:C->S (51 bytes):
00000000  0e 4a 01 20 00 01 00 00  00 00 00 01 06 67 6f 6f |.J. .........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 00 00 29 10 |gle.com.......).|
00000020  00 00 00 00 00 00 0c 00  0a 00 08 cb b3 64 2d 51 |.............d-Q|
00000030  45 47 7d                                         |EG}             |
#0:C<-S (55 bytes):
00000000  0e 4a 81 80 00 01 00 01  00 00 00 01 06 67 6f 6f |.J...........goo|
00000010  67 6c 65 03 63 6f 6d 00  00 01 00 01 c0 0c 00 01 |gle.com.........|
00000020  00 01 00 00 00 74 00 04  ac d9 09 ee 00 00 29 04 |.....t........).|
00000030  d0 00 00 00 00 00 00                             |.......         |
```

## Customizing the Data sent and recieved

There are 6 Callback functions that are called on specific events.
- **ClientReceiveCallback**: Called when the Destination Server Responds with data for the Client (C<-S)
- **ServerReceiveCallback**: Called when data is sent to the Desination Server from the Client. (C->S)
- **ServerStartCallback**: Called when the Proxy Server Makes the connection to the desitnation server.
- **ClientStartCallback**: Called when the Proxy Server Gets a Connection from the The origin of the request.
- **ServerStartCallback**: Called when the Proxy Server Connection is closed.
- **ClientStartCallback**: Called when the Client Connection is closed.

An implimentation of the Callbacks are located in the *logger_callbacks.py* file in the *SocketLogger* Class. 
These can change the information before the data is sent or recieved from the server. 

**Setting the Callback Function:**
```python
logger = SocketLogger(args.log_folder, not args.quiet)
forwarder.setClientReceiveCallback(logger.on_server2client_done_read)
forwarder.setServerReceiveCallback(logger.on_client2server_done_read)
forwarder.setClientStartCallback(logger.on_client2server_new_connection)
forwarder.setServerStartCallback(logger.on_server2client_new_connection)
forwarder.setClientCloseCallback(logger.on_client2server_close_connection)
forwarder.setServerCloseCallback(logger.on_server2client_close_connection)
```



