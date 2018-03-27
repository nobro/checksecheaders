#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Description:
Simple script to check the security of HTTP response headers.

Install:
Requires "requests" to get HTTP Headers:
pip3 install requests

Requires "validators" to validate URL:
pip3 install validators

or install all requirements:
pip3 install -r requirements.txt

Example list:
Valid:
yourname.xyz
 yourname.xyz
www.yourname.xyz
www.yourname.xyz/index.html
http://yourname.xyz
http://yourname.xyz/
https://yourname.xyz
https://yourname.xyz/index.html
someinvaliddomain12312313.com

Usage:
  - run this module without arguments --> get help message
  - run with 'url' --> Select the URL to be parsed - Must be set!
  - run with '--max-redirects' or '-m' --> Select number of maximum redirects, set 0 to disable, default it is set to 2
  - run with '--all' or '-a' --> Show all response headers
  - run with '--useragent' or '-u' --> Set the User-Agent request header. Default it is Firefox 57 for Mac Os X 10.13.
  - run with '--insecure' or '-i' --> Disable certificate verification
  - run with '--timeout' or '-t' --> Set request timeout, default it is set to 5 seconds
  - run with '--description', or '-d ' --> Adds header description and references
  - run with '--help' or '-h' --> shows standard help message

Run:
./checksechead.py URL -a -i -d -m 4 -t 5 -u 'My user agent'

"""

import argparse
import validators
import textwrap
import sys
import requests
import json
import random
from terminaltables import SingleTable


# terminal colors
redcolor = '\033[0;41;1m'
yellowcolor = '\033[0;43;1m'
greencolor = '\033[0;42;1m'
endcolor = '\033[0m'

headers_http_dict = {
    'Content-Security-Policy': [" Content Security Policy (CSP) is an added layer of security that helps to "
                                "detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) "
                                "and data injection attacks. These attacks are used for everything from data theft to "
                                "site defacement or distribution of malware."
                                'Example meta tag: <meta http-equiv="Content-Security-Policy" content="default-src '
                                '\'self\'; img-src https://*; child-src \'none\';">'
                                "[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", yellowcolor],
    'X-Content-Type-Options': [' The X-Content-Type-Options response HTTP header is a marker used by the server '
                               'to indicate that the MIME types advertised in the Content-Type headers should not be '
                               'changed and be followed. This allows to opt-out of MIME type sniffing, or, in other '
                               'words, it is a way to say that the webmasters knew what they were doing.'
                               '[REFERENCE]: https://developer.mozilla.org/en-US/'
                               'docs/Web/HTTP/Headers/X-Content-Type-Options', yellowcolor],
    'X-Xss-Protection': [" The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome "
                         "and Safari that stops pages from loading when they detect reflected cross-site scripting "
                         "(XSS) attacks. Although these protections are largely unnecessary in modern browsers when "
                         "sites implement a strong Content-Security-Policy that disables the use of inline JavaScript "
                         "('unsafe-inline'), they can still provide protections for users of older web browsers that "
                         "don't yet support CSP.."
                         '[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection',
                         yellowcolor],
    'X-Frame-Options': [' Provides Clickjacking protection. Values:'
                        'deny - no rendering within a frame'
                        'sameorigin - no rendering if origin mismatch'
                        'allow-from: DOMAIN - allow rendering if framed by frame loaded from DOMAIN'
                        '[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
                        yellowcolor],
    'X-Permitted-Cross-Domain-Policies': [' A cross-domain policy file is an XML document that grants a web '
                                          'client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily '
                                          'limited to these), permission to handle data across domains. When clients '
                                          'request content hosted on a particular source domain and that content make '
                                          'requests directed towards a domain other than its own, the remote domain '
                                          'needs to host a cross-domain policy file that grants access to the source '
                                          'domain, allowing the client to continue the transaction. Normally a '
                                          'meta-policy is declared in the master policy file, but for those who can’t '
                                          'write to the root directory, they can also declare a meta-policy using the '
                                          'X-Permitted-Cross-Domain-Policies HTTP response header.'
                                          '[REFERENCE]: https://www.owasp.org/index.php/OWASP_'
                                          'Secure_Headers_Project#xpcdp', redcolor],
    'Referrer-Policy': [' The Referrer-Policy HTTP header governs which referrer information, sent in the '
                        'Referer header, should be included with requests made. '
                        '[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
                        yellowcolor],
    'Server': [' Contains information about the software used by the origin server to handle the request.'
               '[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server', greencolor],
    'X-Powered-By': ['[INFO] Specifies the technology (e.g. ASP.NET, PHP, JBoss) supporting the web application '
                     '(version details are often in X-Runtime, X-Version, or X-AspNet-Version)'
                     '[REFERENCE]: https://en.wikipedia.org/wiki/List_of_HTTP_header_fields', greencolor],
    'Cache-Control': [' Used to specify directives that must be obeyed by all caching mechanisms along'
                      ' the request-response chain.',
                      greencolor],
    'Pragma': [' Implementation-specific fields that may have various effects '
               'anywhere along the request-response chain.', greencolor],
    'Last-Modified': ['[INFO] The last modified date for the requested object '
                      '(in "HTTP-date" format as defined by RFC 7231)',
                      greencolor],
    'Expires': [' Gives the date/time after which the response is considered stale'
                ' (in "HTTP-date" format as defined by RFC 7231)', greencolor],
    'Etag': ['An identifier for a specific version of a resource, often a message digest', greencolor],
}

headers_http_separate_dict = {
    'Content-Type': 'UTF-8 Character Encoding decreases the likelihood that '
                    'malicious character conversion could happen',
    'Access-Control-Allow-Origin':  '[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/'
                                    'Headers/Access-Control-Allow-Origin'
}

headers_https_dict = {
    'Strict-Transport-Security': [" HTTP Strict-Transport-Security (HSTS) enforces secure (HTTP over SSL/TLS) "
                                  "connections to the server. This reduces impact of bugs in web applications leaking "
                                  "session data through cookies and external links and defends against "
                                  "Man-in-the-middle attacks. HSTS also disables the ability for user's to ignore"
                                  " SSL negotiation warnings. [REFERENCE]: https://developer.mozilla.org/en-US/docs/"
                                  "Web/HTTP/Headers/Strict-Transport-Security", redcolor],
    'Public-Key-Pins': [" The Public Key Pinning Extension for HTTP (HPKP) is a security header that tells a web"
                        " client to associate a specific cryptographic public key with a certain web server to prevent"
                        " MITM attacks with forged certificates."
                        '[REFERENCE]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning',
                        yellowcolor],
    'Public-Key-Pins-Report-Only': [" The HTTP Public-Key-Pins-Report-Only response header sends reports of"
                                    " pinning violation to the report-uri specified in the header but, unlike "
                                    "Public-Key-Pins still allows browsers to connect to the server if the pinning "
                                    "is violated."
                                    '[REFERENCE]: https://developer.mozilla.org/en-US/docs/'
                                    'Web/HTTP/Headers/Public-Key-Pins-Report-Only', yellowcolor]
}


def get_random_user_agent():
    """Returns a random user agent."""

    chrome = ('Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
              'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36')
    firefox = ('Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) '
               'Gecko/20100101 Firefox/54.0',
               'Mozilla/5.0 (X11; Linux x86_64; rv:10.0) '
               'Gecko/20150101 Firefox/47.0 (Chrome)',
               'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) '
               'Gecko/20100101 Firefox/57.0')
    safari = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) '
              'Version/9.1.2 Safari/601.7.7',)
    user_agents = chrome + firefox + safari
    user_agent = random.choice(user_agents)
    return user_agent


def table_info_https(info):
    """Print info about header inside a table."""
    table_data = [
        ['[INFO]', ''],  # One row. Two columns. Long string will replace this empty string.
    ]
    table = SingleTable(table_data)

    # Calculate newlines.
    max_width = table.column_max_width(1)
    wrapped_string = textwrap.fill(headers_https_dict[info][0], max_width)
    table.table_data[0][1] = wrapped_string

    return table.table


def table_info_http(info):
    """Print info about header inside a table."""
    table_data = [
        ['[INFO]', ''],  # One row. Two columns. Long string will replace this empty string.
    ]
    table = SingleTable(table_data)

    # Calculate newlines.
    max_width = table.column_max_width(1)
    wrapped_string = textwrap.fill(headers_http_dict[info][0], max_width)
    table.table_data[0][1] = wrapped_string

    return table.table


def table_info_separate(info):
    """Print info about header inside a table."""
    table_data = [
        ['[INFO]', ''],  # One row. Two columns. Long string will replace this empty string.
    ]
    table = SingleTable(table_data)

    # Calculate newlines.
    max_width = table.column_max_width(1)
    wrapped_string = textwrap.fill(headers_http_separate_dict[info], max_width)
    table.table_data[0][1] = wrapped_string

    return table.table


def check_url(url):
    """Uses validators to validate a URL and strip whitespaces"""

    # strip whitespaces from beginning or end of string
    url = url.strip()
    # check if valid url, to permit only public IP addresses set public=True
    if validators.url(url):
        return url
    else:
        if not url.startswith('http://') or not url.startswith('https://'):
            print('[!] ' + redcolor + 'Input does not start with http:// or https://.' + endcolor)
            choice = input('[!] ' + 'Adding http:// by default. Do you want to add https:// ? [y/n]')
            if choice == 'y':
                url = 'https://' + url
                print('[!] Adding https:// to input')
            elif choice == 'n':
                url = 'http://' + url
                print('[!] Adding http:// to input')
            else:
                raise ValueError('[!] ' + redcolor + 'Invalid input.' + endcolor + ' Press y for YES and n for No.')
            if validators.url(url):
                return url
            else:
                raise ValueError('[!] ' + redcolor + 'URL is not correct.' + endcolor +
                                 ' Use something like: http://domain.tld')


def get_headers(url, max_redirects, all_headers, user_agent, insecure, timeout):
    """Uses requests library to get headers"""

    with requests.Session() as s:
        s.max_redirects = max_redirects
        s.headers.update({'User-Agent': user_agent})
        if insecure:
            r = s.head(url, verify=False, timeout=timeout)
        else:
            r = s.head(url, timeout=timeout)
        if all_headers:
            print('[!] All request headers: ')
            print(json.dumps(dict(s.headers), sort_keys=True, indent=4))
            print('[!] All response headers: ')
            print(json.dumps(dict(r.headers), sort_keys=True, indent=4))
    return r


def check_headers(url, r, description):
    """Parse headers and check security issues"""

    if url.startswith('https://'):
        for k, v in headers_https_dict.items():
            if k in r.headers.keys():
                print('[*] ' + greencolor + k + endcolor + ' is set with value: ' + r.headers[k])
            else:
                print('[!] ' + headers_https_dict[k][1] + k + endcolor + ' header not found')
            if description:
                print(table_info_https(k))

    for k, v in headers_http_dict.items():
        if k in r.headers.keys():
            print('[*] ' + greencolor + k + endcolor + ' is set with value: ' + r.headers[k])
        else:
            print('[!] ' + headers_http_dict[k][1] + k + endcolor + ' header not found')
            if k == 'Content-Security-Policy':
                print('[INFO] Alternatively, a <meta> element can be used to configure a policy')
            if k == 'X-Permitted-Cross-Domain-Policies':
                print('[INFO] Check crossdomain.xml')
        if description:
            print(table_info_http(k))

    # Old servers may user X-Content-Security-Policy
    # if X-Content-Security-Policy' in r.headers.keys():
        # print('[*] ' + greencolor + 'X-Content-Security-Policy' + endcolor + ' is set with value: ' +
        # r.headers['X-Content-Security-Policy'])

    # Access-Control-Allow-Origin should not be *
    if 'Access-Control-Allow-Origin' in r.headers.keys():
        print('[*] ' + greencolor + 'Access-Control-Allow-Origin' + endcolor + ' is set with value: '
              + r.headers['Access-Control-Allow-Origin'] + ' , it should not be set to "*"')
        if 'Vary' in r.headers.keys():
            print('[*] ' + greencolor + 'Vary' + endcolor + ' is set with value: ' + r.headers['Vary'])
        else:
            print('[-] Vary header was not found')
    else:
        print('[-] Access-Control-Allow-Origin header was not found')
    if description:
        print(table_info_separate('Access-Control-Allow-Origin'))

    # Encoding
    if 'Content-Type' in r.headers.keys():
        if 'text/html; charset=utf-8' in r.headers['Content-Type']:
            print('[*] ' + greencolor + 'Charset' + endcolor + 'is set with value utf-8')
        else:
            print('[-] Charset is set with value: ' + r.headers['Content-Type'])
    else:
        print('[-] Content-Type header was not found')
    if description:
        print(table_info_separate('Content-Type'))


def main():
    parser = argparse.ArgumentParser(
        prog='checksechead.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # ANSI Shadow
        description=textwrap.dedent('''\
        
 ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗    ███████╗███████╗ ██████╗    ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝    ██╔════╝██╔════╝██╔════╝    ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
██║     ███████║█████╗  ██║     █████╔╝     ███████╗█████╗  ██║         ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
██║     ██╔══██║██╔══╝  ██║     ██╔═██╗     ╚════██║██╔══╝  ██║         ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
╚██████╗██║  ██║███████╗╚██████╗██║  ██╗    ███████║███████╗╚██████╗    ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
 ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝

'''),
        epilog='''Simple script to check the security headers for a URL''')
    parser.add_argument('url', metavar='URL', type=str, help='Target URL')  # required param
    parser.add_argument('-m', '--max-redirects', dest='max_redirects', default=2, type=int,
                        help='Max redirects, set 0 to disable, default it is set to 2.')
    parser.add_argument('-t', '--timeout', dest='timeout', default=5, type=int,
                        help='Set the server timeout for a request, default it is set to 5 seconds.')
    parser.add_argument('-a', '--all', action='store_true', help='Show all response headers.')
    parser.add_argument('-u', '--useragent', metavar='User-Agent', type=str, default=get_random_user_agent(),
                        help='Set the User-Agent request header')
    parser.add_argument('-i', '--insecure', action='store_true', help='Disable certificate verification.')
    parser.add_argument('-d', '--description', action='store_true', help='Adds header description and references .')

    args = parser.parse_args()

    if args.url:
        try:
            url = check_url(args.url)
            print('[*] Getting Headers for: ' + url)
        except Exception as e:
            print('[!] ' + redcolor + 'Error in checking input URL: ' + endcolor + str(e))
            parser.print_help()
            sys.exit(1)
        
        try:
            r = get_headers(url, args.max_redirects, args.all, args.useragent, args.insecure, args.timeout)
        except Exception as e:
            print('[!] ' + redcolor + 'Error in request: ' + endcolor + str(e))
            sys.exit(1)
        
        try:
            check_headers(url, r, args.description)
        except Exception as e:
            print('[!] ' + redcolor + 'Error in header parser: ' + endcolor + str(e))
       
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
