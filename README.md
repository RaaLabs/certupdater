# certupdater

Get the LetsEncrypt certificate files for a domain,

Will start a http and http listener for the domain given via the `-domain` flag, and store the key and the certificates files in the `-certDir`.

Certificates are valid for 3 months, they will be renewed 30 days before they expire.

## Flags

```bash
  -certDir string
        specify the full path of where to store the key and certificate
  -daemon
        Set to true do run in daemon mode. The certificate will be automatically renewed 30 days before it expires, and the corresponding .key and .crt file will be updated .
  -domain string
        the domain name to create a certificate for
```

## Create docker image

`docker build -t certupdater:0.1.0 .`

## Run with docker run

docker run -it --rm -v '/my/cert/folder/destination/:/certs/:rw' -p 80:80 -p 443:443 -e DAEMON=false -e USER_FOLDER=/certs -e PROD=false -e DOMAIN=my.super.cool.domain.com certupdater:0.1.0
