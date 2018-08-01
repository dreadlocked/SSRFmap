### SSRFmap

A simple service scanner for Server Side Request Forgery vulnerabilities.

#### Installation
```
bundle install
```

#### Options

```
-u, --url URL                    [Required] Vulnerable URL
-r, --range TARGET RANGE         [Optional] Target IP range to scan by CIDR (default: 127.0.0.1/32
-t, --target TARGET URL          [Optional] Target URL address or hostname
-d, --data POST_PARAMETERS       [Optional] POST parameters quoted: 'param1=a&param2=b'
-m, --method METHOD              [Optional] HTTP Verb to use, default is GET
    --regex REGEX                [Optional] String to identify false results (in case target always returns 200 OK)
-l, --length LENGTH              [Optional] Response length to identify false results (in case target always returns 200 OK)
-T, --threads LEVEL              [Optional] Aggressivity level [1,2,3,4,5], more aggressive means more requests per second. (default: 3)
-p, --port PORT                  [Optional] Scans for one port
-A, --all                        [Optional] Scan all ports (only in scan mode)
    --base64                     [Optional] Encode payload in base64
-h, --help                       Prints this help

```
#### Usage examples

Request a single resource via GET request
```
ruby ssrfmap.rb --url http://www.example.com/controller?url=_SSRF_ --target http://169.254.169.254/
```

Request a single resource via POST request
```
ruby ssrfmap.rb --url http://www.example.com/controller --data "url=_SSRF_" --target http://169.254.169.254/
```

Default range scan on 127.0.0.1/32 via GET requests
```
ruby ssrfmap.rb --url http://www.example.com/controller?url=_SSRF_
```

Range scan on 192.168.0.0/24 via GET requests
```
ruby ssrfmap.rb --url http://www.example.com/controller?url=_SSRF_ --range 192.168.0.0/24
```

Specify a regex for those website who always return 200 OK
```
ruby ssrfmap.rb --url http://www.example.com --data "{\"url\":\"_SSRF_\"}" --regex "Example Domain"
```

#### Dependencies
                    
Gem  | Version
------------- | -------------
typhoeus | *
netaddr | 1.5.1
