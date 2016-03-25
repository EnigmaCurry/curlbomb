#!/bin/env python3
"""curlbomb - a personal HTTP server for serving a one-time-use bash
script (or other file)

You know all those docs for cool dev tools that start out by telling
you to install their software in one line, like this?

    bash <(curl -s http://example.com/install.sh)

I call that a curl bomb... I don't know if anyone else does.

This script is an HTTP server that will serve that script to a client
exactly once and then quit. Yea, you could just use "python -m http.server", 
really this is just a bit more than that.

MIT Licensed

Ryan McGuire <ryan@enigmacurry.com>
http://github.com/EnigmaCurry/curlbomb
"""

import socket
import http.server
import socketserver
import ssl
import os
import sys
from io import BytesIO
from collections import defaultdict
import uuid
import argparse

class CurlBomb(http.server.BaseHTTPRequestHandler):
    # Per handler_id state vars:
    __handler_vars = defaultdict(lambda: {'num_gets': 0})
    
    def __init__(self, handler_id, resourcef, allowed_gets=1, require_knock=False, mime_type='text/plain', *args):
        """Server a file like resource
        
          handler_id    - Unique id for the handler 
          resourcef     - A resource file like object
          allowed_gets  - Number of gets allowed before quiting
          require_knock - Require the handler_id in a request header called X-knock
          mime_type     - The mime type the server should declare the content as
          *args         - The rest of the BaseHTTPRequestHandler args

          End users should use get_handler() instead of this class initializer
        """
        self.__handler_id = handler_id 
        self.__resourcef = resourcef
        self.__allowed_gets = allowed_gets
        self.__require_knock = require_knock
        self.__mime_type = mime_type
        http.server.BaseHTTPRequestHandler.__init__(self, *args)

    def get_vars(self):
        return self.__handler_vars[self.__handler_id]
        
    def do_GET(self):
        if self.__allowed_gets == 0 or self.get_vars()['num_gets'] < self.__allowed_gets:
            self.get_vars()['num_gets'] += 1
            if self.__require_knock:
                if self.headers.get('X-knock', False) != self.__handler_id:
                    self.send_response(401)
                    self.wfile.write(b"echo 'Invalid knock'")
                    print("Invalid knock")
                    return
            self.send_response(200)
            self.send_header("Content-type", self.__mime_type)
            self.end_headers()
            self.wfile.write(self.__resourcef.read())
            
        if self.__allowed_gets > 0 and self.__allowed_gets <= self.get_vars()['num_gets']:
            print("Served resource {} times. Done.".format(self.get_vars()['num_gets']))
            os._exit(0)
        else:
            self.__resourcef.seek(0)

    @classmethod
    def get_handler(cls, resourcef, allowed_gets=1, require_knock=False, mime_type='plain/text'):
        """Get a parameterized CurlBomb class

        It seems an odd choice that the Python socket api requires
        class objects rather than instance objects, but this gets
        around the problem of needing configurable instantiation.
        """
        handler_id = uuid.uuid4().hex
        def handler(*args):
            f = CurlBomb(
                handler_id, resourcef, allowed_gets, require_knock, mime_type, *args)
            return f
        handler.require_knock = require_knock
        handler.handler_id = handler_id
        return handler

    @classmethod
    def get_server(cls, handler, port="random", ssl_cert=None, verbose=True, shell_command="bash"):
        if port == "random":
            port = 0
        else:
            port = int(port)
            
        httpd = socketserver.TCPServer(("", port), handler)
        if ssl_cert is not None:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=ssl_cert, server_side=True)
        if verbose:
            if handler.require_knock:
                knock = ' -H "X-knock: {}"'.format(handler.handler_id)

            if shell_command is None:
                cmd = "curl http{ssl}://{ip}:{port}{knock}".format(
                    ssl="s" if ssl_cert is not None else "",
                    ip=socket.gethostbyname(socket.gethostname()),
                    port=httpd.socket.getsockname()[1],
                    knock=knock)
            else:
                cmd = "{shell_command} <(curl http{ssl}://{ip}:{port}{knock})".format(
                    shell_command=shell_command,
                    ssl="s" if ssl_cert is not None else "",
                    ip=socket.gethostbyname(socket.gethostname()),
                    port=httpd.socket.getsockname()[1],
                    knock=knock
                )
                
            print("Client command:")
            print("")
            print("  " + cmd)
            print("")
        return httpd

def argparser(formatter_class=argparse.HelpFormatter):
    parser = argparse.ArgumentParser(description='curlbomb', formatter_class=formatter_class)
    parser.add_argument('-k', '--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)")
    parser.add_argument('-n', dest="num_gets", help="Number of times to serve resource (default:1)", type=int, default=1)
    parser.add_argument('-p', dest="port", help="TCP port number to use (default:random)", default="random")
    parser.add_argument('-q', dest="quiet", action="store_true", help="Be quiet")
    parser.add_argument('-c', dest="command", help="The the shell command to curlbomb into (default is to detect #!interpreter)", default="AUTO")
    parser.add_argument('--ssl', metavar="CERTIFICATE", help="Use SSL with the given certificate")
    parser.add_argument('--mime-type', help="The content type to serve", default="text/plain")
    parser.add_argument('--survey', help="Just a survey mission, no bomb run", action="store_true")
    parser.add_argument('resource', metavar="FILE", help="File to serve (or don't specify for stdin)", nargs='?', default=sys.stdin)
    return parser

def main():
    parser = argparser()
    args = parser.parse_args()
    
    if args.resource == sys.stdin and sys.stdin.isatty():
        parser.print_help()
        print("\nYou must specify a file or pipe one to this command's stdin")
        exit(1)
    if args.resource == sys.stdin or args.resource == '-':
        resource = BytesIO(sys.stdin.buffer.read())
    else:
        resource = open(args.resource, 'br')

    if args.survey:
        # Turn off shell_command entirely, just show a raw curl command
        shell_command = None
    else:
        #Detect if the input has a shebang so we can detect the shell command to display
        if args.command == "AUTO":
            line = resource.readline(500)
            resource.seek(0)
            if line.startswith(b'#!'):
                shell_command = line[2:].decode("utf-8").rstrip()
            else:
                shell_command = "bash"
        else:
            shell_command = args.command
            
    try:
        handler = CurlBomb.get_handler(
            resource, allowed_gets=args.num_gets,
            require_knock=not args.disable_knock, mime_type=args.mime_type)
        httpd = CurlBomb.get_server(handler, port=args.port, verbose=not args.quiet, ssl_cert=args.ssl, shell_command=shell_command)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    finally:
        resource.close()    
    
if __name__ == "__main__":
    main()
