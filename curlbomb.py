#!/bin/env python3
"""curlbomb - a personal HTTP server for serving one-time-use shell scripts.

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
import time
import threading
import subprocess
from io import BytesIO
from collections import defaultdict
import uuid
import argparse

__version__ = "1.0.11"

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
        self._server = None
        self.handler_id = handler_id 
        self.__resourcef = resourcef
        self.__allowed_gets = allowed_gets
        self.__require_knock = require_knock
        self.__mime_type = mime_type
        http.server.BaseHTTPRequestHandler.__init__(self, *args)

    def get_vars(self):
        return self.__handler_vars[self.handler_id]

    def do_GET(self):
        if self.__allowed_gets == 0 or self.get_vars()['num_gets'] < self.__allowed_gets:
            self.get_vars()['num_gets'] += 1
            if self.__require_knock:
                if self.headers.get('X-knock', False) != self.handler_id:
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
    def get_server(cls, handler, port="random", ssl_cert=None,
                   verbose=True, shell_command="bash", http_fetcher="curl -sL", ssh=None):
        if port == "random":
            port = 0
        else:
            port = int(port)

        class ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True
            
        httpd = ReusableTCPServer(("", port), handler)
        port = httpd.socket.getsockname()[1]
        host=socket.gethostbyname(socket.gethostname())
                                
        ssh_conn = None
        if ssh:
            # Forward curlbomb through SSH to another host
            ssh_parts = ssh.split(":")
            ssh_host = ssh_parts[0]
            if '@' in ssh_host:
                user, host = ssh_host.split('@')
            ssh_port = 22
            http_port = port
            if len(ssh_parts) == 3:
                ssh_port = ssh_parts[1]
                http_port = ssh_parts[2]
            elif len(ssh_parts) == 2:
                http_port = ssh_parts[1]
            ssh_forward = "0.0.0.0:{http_port}:localhost:{port}".format(
                port=port, host=host, http_port=http_port)
            ssh_conn = SSHRemoteForward(ssh_host, ssh_forward, ssh_port)
            ssh_conn.start()
            if not ssh_conn.wait_connected():
                print(ssh_conn.last_msg)
                sys.exit(1)
            port = http_port
        httpd.ssh_conn = ssh_conn
        
        if ssl_cert is not None:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=ssl_cert, server_side=True)
        if verbose:
            knock = ""
            if handler.require_knock:
                if http_fetcher.startswith("wget"):
                    knock = ' --header="X-knock: {}"'.format(handler.handler_id)
                else:
                    knock = ' -H "X-knock: {}"'.format(handler.handler_id)

            if shell_command is None:
                cmd = "{http_fetcher} http{ssl}://{host}:{port}{knock}".format(
                    http_fetcher=http_fetcher,
                    ssl="s" if ssl_cert is not None else "",
                    host=host,
                    port=port,
                    knock=knock)
            else:
                cmd = "{shell_command} <({http_fetcher} http{ssl}://{host}:{port}{knock})".format(
                    http_fetcher=http_fetcher,
                    shell_command=shell_command,
                    ssl="s" if ssl_cert is not None else "",
                    host=host,
                    port=port,
                    knock=knock
                )
                
            if ssh_conn:
                print("Client command (ssh tunneled):")
            else:
                print("Client command:")
            print("")
            print("  " + cmd)
            print("")
        return httpd

class SSHRemoteForward(threading.Thread):
    def __init__(self, host, remote_forward, ssh_port=22):
        """Start an SSH connection to the specified host and remotely forward a port"""
        self.host = host
        self.ssh_port = str(ssh_port)
        self.remote_forward = remote_forward
        self._kill = False
        self._connected = False
        self._lines = []
        threading.Thread.__init__(self)

    def run(self):
        proc = subprocess.Popen(
            ['ssh','-v','-p',self.ssh_port,'-N','-R',self.remote_forward,self.host],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while True:
            line = proc.stdout.readline()
            self._lines.append(line)
            if line == b'':
                self._kill = True
                break
            elif line.startswith(b"Authenticated to"):
                self._connected = True
                break
        while True:
            if self._kill:
                self.last_msg = self._lines[-2].decode("utf-8")
                proc.kill()
                break
            time.sleep(0.1)

    def wait_connected(self):
        try:
            while not self._kill:
                if self._connected:
                    return True
                time.sleep(0.1)
            return False
        except KeyboardInterrupt:
            self.kill()
    
    def kill(self):
        self._kill = True
        
def argparser(formatter_class=argparse.HelpFormatter):
    parser = argparse.ArgumentParser(description='curlbomb', formatter_class=formatter_class)
    parser.add_argument('-k', '--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)")
    parser.add_argument('-n', dest="num_gets", help="Number of times to serve resource (default:1)", type=int, default=1)
    parser.add_argument('-p', dest="port", help="TCP port number to use (default:random)", default="random")
    parser.add_argument('-q', dest="quiet", action="store_true", help="Be quiet")
    parser.add_argument('-c', dest="command", help="The the shell command to curlbomb into (default is to detect #!interpreter)", default="AUTO")
    parser.add_argument('-w', dest="wget", help="Output wget command rather than curl", action="store_true")
    parser.add_argument('--ssh', metavar="SSH_FORWARD", help="Forward curlbomb through another host via SSH - [user@]host[:ssh_port][:http_port]", default=None)
    parser.add_argument('--ssl', metavar="CERTIFICATE", help="Use SSL with the given certificate")
    parser.add_argument('--mime-type', help="The content type to serve", default="text/plain")
    parser.add_argument('--survey', help="Just a survey mission, no bomb run", action="store_true")
    parser.add_argument('--version', help="Print curlbomb version", action="store_true")
    parser.add_argument('resource', metavar="FILE", help="File to serve (or don't specify for stdin)", nargs='?', default=sys.stdin)
    return parser

def main():
    parser = argparser()
    args = parser.parse_args()

    if args.version:
        print(__version__)
        exit(0)
    
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

    if args.wget:
        http_fetcher = "wget -q -O -"
    else:
        http_fetcher = "curl -LSs"
            
    try:
        handler = CurlBomb.get_handler(
            resource, allowed_gets=args.num_gets,
            require_knock=not args.disable_knock, mime_type=args.mime_type)
        httpd = CurlBomb.get_server(handler, port=args.port,
                                    verbose=not args.quiet,
                                    ssl_cert=args.ssl,
                                    shell_command=shell_command,
                                    http_fetcher=http_fetcher,
                                    ssh=args.ssh)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            if httpd.ssh_conn:
                httpd.ssh_conn.kill()
    finally:
        resource.close()    
    
if __name__ == "__main__":
    main()
