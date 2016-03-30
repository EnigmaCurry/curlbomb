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

import eventlet
from eventlet.green import socket
from eventlet.green import SocketServer
HTTPServer = eventlet.import_patched('HTTPServer',
                        socket=socket, SocketServer=SocketServer)

from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

import ssl
import os
import sys
import time
import threading
import subprocess
import tempfile
import logging
from io import BytesIO
from collections import defaultdict
import uuid
import argparse

__version__ = "1.0.17"

logging.basicConfig()
log = logging.getLogger('curlbomb')
log.setLevel(level=logging.INFO)

class ServiceShutdownException(Exception):
    pass

class CurlBomb(BaseHTTPRequestHandler):
    # Per handler_id state vars:
    __handler_vars = defaultdict(lambda: {
        'num_gets': 0, # Number of times resource has been retrieved by client
        'post_backs': 0 #Data posted back from the client
    })
    
    def __init__(self, handler_id, resourcef, allowed_gets=1, require_knock=False,
                 mime_type='text/plain', allow_post_backs=False, log_post_backs=False,
                 shutdown_handler=None, *args):
        """Server a file like resource
        
          handler_id       - Unique id for the handler 
          resourcef        - A resource file like object
          allowed_gets     - Number of gets allowed before quiting
          require_knock    - Require the handler_id in a request header called X-knock
          mime_type        - The mime type the server should declare the content as
          allow_post_backs - Allow client to post data back to the server. 
                             Delays server termination until post_backs == allowed_gets
          log_post_backs   - Log post backs to stdout
          shutdown_handler - Callback to run when we need to shutdown
          *args            - The rest of the BaseHTTPRequestHandler args

          End users should use get_handler() instead of this class initializer
        """
        self._server = None
        self.handler_id = handler_id 
        self.__resourcef = resourcef
        self.__allowed_gets = allowed_gets
        self.__require_knock = require_knock
        self.__allow_post_backs = allow_post_backs
        self.__log_post_backs = log_post_backs
        self.__mime_type = mime_type
        self.__shutdown_handler = shutdown_handler
        
        BaseHTTPRequestHandler.__init__(self, *args)
        
    def get_vars(self):
        return self.__handler_vars[self.handler_id]

    def do_GET(self):
        if self.__allowed_gets == 0 or self.get_vars()['num_gets'] < self.__allowed_gets:
            self.get_vars()['num_gets'] += 1
            if self.__require_knock and not self.validate_knock():
                return
            # Client is allowed to get:
            self.send_response(200)
            self.send_header("Content-type", self.__mime_type)
            self.end_headers()
            self.wfile.write(self.__resourcef.read())
        else:
            # Client is not allowed to get any more:
            self.send_response(405)
            self.end_headers()
            self.wfile.write(b"Client is not allowed to GET anymore")

        self.__resourcef.seek(0)

        self.shutdown_if_ready()

    def do_PUT(self):
        self.do_POST()
        
    def do_POST(self):
        if not self.__allow_post_backs:
            self.send_response(405)
            self.end_headers()
            self.wfile.write(b"This server is not configured to allow data upload.")
            return
        if self.__require_knock and not self.validate_knock():
            return
        if self.headers.get('Transfer-Encoding', None) != "chunked":
            self.send_response(400)
            self.end_headers()
            self.wfile.write("Content must be sent Transfer-Encoding: chunked")
            return

        self.get_vars()['post_backs'] += 1
        self.send_response(100)
        self.send_response(200)
        self.end_headers()

        # Read chunked formatted data
        # See : http://www.jmarshall.com/easy/http/#http1.1c2
        # and : https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
        start = time.time()
        while True:
            # Read next chunk size:
            chunk_line = self.rfile.readline()
            log.debug("Chunk size line: {}".format(chunk_line))
            if chunk_line == b'':
                log.debug("empty chunk size")
                break
            chunk_line = chunk_line.rstrip().split(b";")[0]
            chunk_size = int(chunk_line, base=16)
            if chunk_size == 0:
                log.debug("Last chunk found, breaking read loop")
                break
            # Read chunk:
            chunk = self.rfile.read(chunk_size+2)
            log.debug("Chunk line: {}".format(chunk))
            assert chunk.endswith(b'\r\n')
            chunk = chunk[:-2]
            if self.__log_post_backs:
                for c in chunk.splitlines():
                    print("{}:{} - {chunk}".format(*self.client_address, chunk=c.decode("utf-8")))

        self.wfile.write(bytes("\-\-\ncurlbomb finished in {:.2f}s\n".format(time.time() - start), "utf-8"))
        log.debug("Done with do_POST")
        
        self.shutdown_if_ready()

    def log_message(self, format, *args):
        log.info("{} - - [{}] {}".format(
            self.client_address[0],
            self.log_date_time_string(),
            format%args))

    def log_error(self, format, *args):
        log.error("{} - - [{}] {}".format(
            self.client_address[0],
            self.log_date_time_string(),
            format%args))

    def handle_expect_100(self):
        pass
        
    def shutdown_if_ready(self):
        """Shutdown if it's time to shutdown"""
        # If the resource has been retrieved all the times it's allowed:
        if self.__allowed_gets > 0 and self.__allowed_gets <= self.get_vars()['num_gets']:
            num_post_backs = self.get_vars()['post_backs']
            # If we're still waiting for post backs:
            if self.__allow_post_backs and num_post_backs < self.__allowed_gets:
                log.info("Waiting for {} more post backs from client".format(self.__allowed_gets - num_post_backs))
            else:
                # Shutdown:
                log.info("Served resource {} times. Done.".format(self.get_vars()['num_gets']))
                self.shutdown()

    def shutdown(self):
        if self.__shutdown_handler is None:
            raise RuntimeError("shutdown handler is not registered")
        t = threading.Thread(target=self.__shutdown_handler)
        t.daemon = True
        t.start()
            
    def validate_knock(self):
        if self.headers.get('X-knock', False) != self.handler_id:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Invalid or missing knock")
            log.info("Invalid knock")
            return False
        return True
    
    @classmethod
    def get_handler(cls, resourcef, allowed_gets=1, require_knock=False,
                    mime_type='plain/text', allow_post_backs=False, log_post_backs=False,
                    shutdown_handler=None):
        """Get a parameterized CurlBomb class

        It seems an odd choice that the Python socket api requires
        class objects rather than instance objects, but this gets
        around the problem of needing configurable instantiation.
        """
        handler_id = uuid.uuid4().hex
        def handler(*args):
            f = CurlBomb(
                handler_id, resourcef, allowed_gets, require_knock, mime_type, allow_post_backs,
                log_post_backs, shutdown_handler, *args)
            return f
        handler.require_knock = require_knock
        handler.handler_id = handler_id
        return handler

    @classmethod
    def get_server(cls, resource, allowed_gets=1, require_knock=True,
                   mime_type="text/plain", allow_post_backs=False,
                   port="random", ssl_cert=None, verbose=True, shell_command="bash", http_fetcher="curl -sL",
                   ssh=None, client_logging=False, log_post_backs=False):
        if port == "random":
            port = 0
        else:
            port = int(port)

        class StoppableHTTPServer(HTTPServer):
            def run(self):
                try:
                    self.serve_forever()
                except Keyboardinterrupt:
                    self.shutdown()
                finally:
                    self.server_close()
            def bind_handler(self, RequestHandlerClass):
                self.RequestHandlerClass = RequestHandlerClass
        
        httpd = StoppableHTTPServer(("", port), BaseHTTPRequestHandler)
        port = httpd.socket.getsockname()[1]
        host=socket.gethostbyname(socket.gethostname())

        handler = CurlBomb.get_handler(
            resource, allowed_gets=allowed_gets,
            require_knock=require_knock, mime_type=mime_type,
            allow_post_backs=allow_post_backs, log_post_backs=log_post_backs,
            shutdown_handler=httpd.shutdown)

        # Replace BaseHTTPRequestHandler with the new handler
        httpd.bind_handler(handler)
        
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
                log.error(ssh_conn.last_msg)
                sys.exit(1)
            port = http_port
        httpd.ssh_conn = ssh_conn
        
        if ssl_cert is not None:
            with open(ssl_cert, 'br') as cert_file:
                cert = cert_file.read()
                if cert.startswith(b'-----BEGIN PGP MESSAGE-----'):
                    # Decrypt PGP encrypted certfile:
                    with subprocess.Popen(['gpg','-d'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as p:
                        p.stdin.write(cert)
                        decrypted_cert, err = p.communicate()
                        # Create temporary file to store decrypted cert.
                        # This isn't the most secure method I can think of, but I can't see another
                        # way as the low-level openssl api requires a file and will not accept a string
                        # or file like object.
                        with tempfile.NamedTemporaryFile('wb') as temp_cert:
                            temp_cert.write(decrypted_cert)
                            del decrypted_cert
                            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=temp_cert.name, server_side=True)
                else:
                    httpd.socket = ssl.wrap_socket(httpd.socket, certfile=ssl_cert, server_side=True)
        if verbose:
            knock = ""
            logger = ""
            post_back = ""
            if handler.require_knock:
                if http_fetcher.startswith("wget"):
                    knock = ' --header="X-knock: {}"'.format(handler.handler_id)
                else:
                    knock = ' -H "X-knock: {}"'.format(handler.handler_id)
            if client_logging or log_post_backs:
                logger += " | tee"
                if client_logging:
                    logger += "curlbomb.log"
                if log_post_backs:
                    logger +=" >(curl -T - http{ssl}://{host}:{port}{knock})".format(
                        ssl="s" if ssl_cert is not None else "",
                        host=host,
                        port=port,
                        knock=knock
                    )

            if shell_command is None:
                cmd = "{http_fetcher} http{ssl}://{host}:{port}{knock}{logger}".format(
                    http_fetcher=http_fetcher,
                    ssl="s" if ssl_cert is not None else "",
                    host=host,
                    port=port,
                    knock=knock,
                    logger=logger)
            else:
                cmd = "{shell_command} <({http_fetcher} http{ssl}://{host}:{port}{knock}|tac|tac){logger}".format(
                    http_fetcher=http_fetcher,
                    shell_command=shell_command,
                    ssl="s" if ssl_cert is not None else "",
                    host=host,
                    port=port,
                    knock=knock,
                    logger=logger)
                
            if ssh_conn:
                ("Client command (ssh tunneled):")
            else:
                sys.stderr.write("Client command:\n")
            sys.stderr.write("\n")
            sys.stderr.write("  {}\n".format(cmd))
            sys.stderr.write("\n")
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
        self.join()
        log.info("SSH tunnel closed")
        
def argparser(formatter_class=argparse.HelpFormatter):
    parser = argparse.ArgumentParser(description='curlbomb', formatter_class=formatter_class)
    parser.add_argument('-k', '--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)")
    parser.add_argument('-n', dest="num_gets", help="Number of times to serve resource (default:1)", type=int, default=1)
    parser.add_argument('-p', dest="port", help="TCP port number to use (default:random)", default="random")
    parser.add_argument('-q', dest="quiet", action="store_true", help="Be quiet")
    parser.add_argument('-c', dest="command",
                        help="The the shell command to curlbomb into (default is to detect #!interpreter)", default="AUTO")
    parser.add_argument('-w', dest="wget", help="Output wget command rather than curl", action="store_true")
    parser.add_argument('-l', dest="log_post_backs", action="store_true",
                        help="Log data posted from client(s) to stdout (implies --receive-postback)")
    parser.add_argument('--ssh', metavar="SSH_FORWARD",
                        help="Forward curlbomb through another host via SSH - [user@]host[:ssh_port][:http_port]",
                        default=None)
    parser.add_argument('--ssl', metavar="CERTIFICATE", help="Use SSL with the given certificate file (optionally PGP encrypted)")
    parser.add_argument('--receive-postback', dest="receive_postbacks",
                        help="Wait for client(s) to POST data back after a GET. (requires same knock. "
                        "Delays curlbomb termination until num_posts == num_gets)",
                        action="store_true")
    parser.add_argument('--survey', help="Just a survey mission, no bomb run. "
                        "(just get the script, don't run it)", action="store_true")
    parser.add_argument('--client-logging', dest="client_logging",
                        help="Enable client execution log (curlbomb.log on client)", action="store_true")
    parser.add_argument('--mime-type', help="The content type to serve", default="text/plain")
    parser.add_argument('--version', action="version", version=__version__)
    parser.add_argument('resource', metavar="FILE", nargs='?', default=sys.stdin,
                        help="File to serve (or don't specify for stdin)")
    return parser

def main():
    parser = argparser()
    args = parser.parse_args()

    if args.resource == sys.stdin and sys.stdin.isatty():
        parser.print_help()
        sys.stderr.write("\nYou must specify a file or pipe one to this command's stdin\n")
        exit(1)
    if args.resource == sys.stdin or args.resource == '-':
        resource = BytesIO(sys.stdin.buffer.read())
    else:
        resource = open(args.resource, 'br')

    if args.survey:
        # Turn off shell_command entirely, just show a raw curl command
        shell_command = None
        # Never do client logging in survey mode. 
        args.client_logging = False
        # Never do postback logging either.
        args.log_post_backs = False
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

    if args.log_post_backs:
        # Logging post backs implies we allow post backs:
        args.receive_postbacks = True

    if args.wget:
        http_fetcher = "wget -q -O -"
    else:
        http_fetcher = "curl -LSs"
    
    try:
        # handler = CurlBomb.get_handler(
        #     resource, allowed_gets=args.num_gets,
        #     require_knock=not args.disable_knock, mime_type=args.mime_type,
        #     allow_post_backs=args.receive_postbacks, log_post_backs=args.log_post_backs
        # )
        httpd = CurlBomb.get_server(
            # Handler args:
            resource=resource,
            allowed_gets=args.num_gets,
            require_knock=not args.disable_knock,
            mime_type=args.mime_type,
            allow_post_backs=args.receive_postbacks,
            # Server args:
            port=args.port,
            verbose=not args.quiet,
            ssl_cert=args.ssl,
            shell_command=shell_command,
            http_fetcher=http_fetcher,
            ssh=args.ssh,
            client_logging=args.client_logging,
            log_post_backs=args.log_post_backs,
        )

        # try:
        #     httpd.serve_forever()
        # except KeyboardInterrupt:
        #     pass
        # except ServiceShutdownException:
        #     pass
        # finally:
        #     if httpd.ssh_conn:
        #         httpd.ssh_conn.kill()

        httpd_thread = threading.Thread(None, httpd.run)
        httpd_thread.start()
        try:
            httpd_thread.join()
        except KeyboardInterrupt:
            httpd.shutdown()
            httpd_thread.join()

    finally:
        resource.close()    
    
if __name__ == "__main__":
    main()
