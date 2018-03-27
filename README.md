# Check security haders

A simple script that checks the security of HTTP headers:

Uses socket to get IPs so it is subject to localy configured resolver.

### Install:

Requires **requests** to get HTTP Headers:
```
pip3 install requests
```
Requires **validators** to validate URL:
```
pip3 install validators
```
or install all requirements:
```
pip3 install -r requirements.txt
```

Valid example list:
```
yourname.xyz
 yourname.xyz
www.yourname.xyz
www.yourname.xyz/index.html
http://yourname.xyz
http://yourname.xyz/
https://yourname.xyz
https://yourname.xyz/index.html
someinvaliddomain12312313.com
```

### Usage:
  - run this module without arguments --> get help message
  - run with 'url' --> Select the URL to be parsed - Must be set!
  - run with '--max-redirects' or '-m' --> Select number of maximum redirects, set 0 to disable, default it is set to 2
  - run with '--all' or '-a' --> Show all response headers
  - run with '--useragent' or '-u' --> Set the User-Agent request header. Default it is Firefox 57 for Mac Os X 10.13.
  - run with '--insecure' or '-i' --> Disable certificate verification
  - run with '--timeout' or '-t' --> Set request timeout, default it is set to 5 seconds
  - run with '--description', or '-d ' --> Adds header description and references
  - run with '--help' or '-h' --> shows standard help message

### Run:
./checksechead.py URL -a -i -d -m 4 -t 5 -u 'My user agent'
```
[!] Input does not start with http:// or https://.
[!] Adding http:// by default. Do you want to add https:// ? [y/n]y
[!] Adding https:// to input
[*] Getting Headers for: https://nob.ro
/usr/local/lib/python3.5/site-packages/urllib3/connectionpool.py:858: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  InsecureRequestWarning)
[!] All request headers:
{
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "User-Agent": "My user agent"
}
[!] All response headers:
{
    "CF-RAY": "3e1a481a2a2664cf-FRA",
    "Connection": "keep-alive",
    "Content-Encoding": "gzip",
    "Content-Type": "text/html",
    "Date": "Tue, 23 Jan 2018 11:06:05 GMT",
    "Expect-CT": "max-age=604800, report-uri=\"https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct\"",
    "Last-Modified": "Mon, 01 Jan 2018 14:39:19 GMT",
    "Server": "cloudflare",
    "Set-Cookie": "__cfduid=daceb2201366de810eda42e406ece41611516705565; expires=Wed, 23-Jan-19 11:06:05 GMT; path=/; domain=.nob.ro; HttpOnly",
    "Strict-Transport-Security": "max-age=7776000",
    "X-Content-Type-Options": "nosniff"
}
[!] Public-Key-Pins-Report-Only header not found
[INFO] The HTTP Public-Key-Pins-Report-Only response header sends reports of pinning violation to the report-uri specified in the header but, unlike Public-Key-Pins still allows browsers to connect to the server if the pinning is violated.
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins-Report-Only
-------------------------------------------------------------------------------------
[!] Public-Key-Pins header not found
[INFO] The Public Key Pinning Extension for HTTP (HPKP) is a security header that tells a web client to associate a specific cryptographic public key with a certain web server to prevent MITM attacks with forged certificates.
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning
-------------------------------------------------------------------------------------
[*] Strict-Transport-Security is set with value: max-age=7776000
[INFO] HTTP Strict-Transport-Security (HSTS) enforces secure (HTTP over SSL/TLS) connections to the server. This reduces impact of bugs in web applications leaking session data through cookies and external links and defends against Man-in-the-middle attacks. HSTS also disables the ability for user's to ignore SSL negotiation warnings.\n-------------------------------------------------------------------------------------
[!] X-Xss-Protection header not found
[INFO] This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
-------------------------------------------------------------------------------------
[!] Content-Security-Policy header not found
[INFO] Alternatively, a <meta> element can be used to configure a policy
[INFO] Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.
Example meta tag: <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
-------------------------------------------------------------------------------------
[!] X-Permitted-Cross-Domain-Policies header not found
[INFO] Check crossdomain.xml
[INFO] A cross-domain policy file is an XML document that grants a web client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily limited to these), permission to handle data across domains. When clients request content hosted on a particular source domain and that content make requests directed towards a domain other than its own, the remote domain needs to host a cross-domain policy file that grants access to the source domain, allowing the client to continue the transaction. Normally a meta-policy is declared in the master policy file, but for those who can’t write to the root directory, they can also declare a meta-policy using the X-Permitted-Cross-Domain-Policies HTTP response header.
[REFERENCE]: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#xpcdp
-------------------------------------------------------------------------------------
[!] X-Frame-Options header not found
[INFO] Provides Clickjacking protection. Values:
deny - no rendering within a frame
sameorigin - no rendering if origin mismatch
allow-from: DOMAIN - allow rendering if framed by frame loaded from DOMAIN
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
-------------------------------------------------------------------------------------
[!] X-Powered-By header not found
[INFO] Specifies the technology (e.g. ASP.NET, PHP, JBoss) supporting the web application (version details are often in X-Runtime, X-Version, or X-AspNet-Version)
[REFERENCE]: https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
-------------------------------------------------------------------------------------
[!] Etag header not found
[INFO] An identifier for a specific version of a resource, often a message digest
-------------------------------------------------------------------------------------
[!] Expires header not found
[INFO] Gives the date/time after which the response is considered stale (in "HTTP-date" format as defined by RFC 7231)
-------------------------------------------------------------------------------------
[*] Last-Modified is set with value: Mon, 01 Jan 2018 14:39:19 GMT
[INFO] The last modified date for the requested object (in "HTTP-date" format as defined by RFC 7231)
-------------------------------------------------------------------------------------
[!] Referrer-Policy header not found
[INFO] The Referrer-Policy HTTP header governs which referrer information, sent in the Referer header, should be included with requests made.
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
-------------------------------------------------------------------------------------
[!] Pragma header not found
[INFO] Implementation-specific fields that may have various effects anywhere along the request-response chain.
-------------------------------------------------------------------------------------
[*] X-Content-Type-Options is set with value: nosniff
[INFO] The only defined value, "nosniff", prevents Internet Explorer and Google Chrome from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome, when downloading extensions. This reduces exposure to drive-by download attacks and sites serving user uploaded content that, by clever naming, could be treated by MSIE as executable or dynamic HTML files.
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
-------------------------------------------------------------------------------------
[!] Cache-Control header not found
[INFO] Used to specify directives that must be obeyed by all caching mechanisms along the request-response chain.
-------------------------------------------------------------------------------------
[*] Server is set with value: cloudflare
[INFO] Contains information about the software used by the origin server to handle the request.
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server
-------------------------------------------------------------------------------------
[-] Access-Control-Allow-Origin header was not found
[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
-------------------------------------------------------------------------------------
[-] Charset is set with value: text/html
[INFO] UTF-8 Character Encoding decreases the likelihood that malicious character conversion could happen
-------------------------------------------------------------------------------------
```
