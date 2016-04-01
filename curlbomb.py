#!/bin/env python3
"""curlbomb is an HTTP server for serving one-time-use shell scripts

You know all those docs for cool dev tools that start out by telling
you to install their software in one line, like this?

    bash <(curl -s http://example.com/install.sh)

I call that a curl bomb... I don't know if anyone else does.

This script is an HTTP server that will serve that script to a client
exactly once and then quit. Yea, you could just use "python -m http.server", 
really this is just a bit more than that.

MIT Licensed, see LICENSE.txt

Ryan McGuire <ryan@enigmacurry.com>
http://github.com/EnigmaCurry/curlbomb
"""
import ssl
import socket
import argparse
import sys
import os
import logging
import random
import base64
import subprocess
import threading
import tempfile
import time
from io import BytesIO

import tornado.web
import tornado.ioloop
import tornado.gen

logging.basicConfig()
log = logging.getLogger('curlbomb')
log.setLevel(level=logging.WARN)

def get_version():
    import pkg_resources
    pkg = pkg_resources.get_distribution('curlbomb')
    if __file__.startswith(pkg.location):
        return pkg.version
    else:
        return 'DEV'

class CurlbombBaseRequestHandler(tornado.web.RequestHandler):
    """Base RequestHandler

      Implementations:
       - CurlbombResourceRequestHandler 
       - CurlbombStreamRequestHandler
    """
    
    def initialize(self, resource, state, allowed_gets=1, knock=None,
                   mime_type='text/plain', allow_post_backs=False, log_post_backs=False):
        """Arguments:
        
          resource         - A file like object to serve the contents of
          state            - State dictionary to maintain across requests
          allowed_gets     - Number of gets allowed before quiting
          knock            - The required X-knock header the client must send, or None
          mime_type        - The mime type the server should declare the content as
          allow_post_backs - Allow client to post data back to the server. 
                             Delays server termination until post_backs == allowed_gets
          log_post_backs   - Log post backs to stdout
          *args            - The rest of the RequestHandler args
          **kwargs         - The rest of the RequestHandler kwargs
        """
        self._resource = resource
        self._allowed_gets = allowed_gets
        self._knock = knock
        self._mime_type = mime_type
        self._allow_post_backs = allow_post_backs
        self._log_post_backs = log_post_backs

        self._state = state
                
    def prepare(self):
        self.request.start_time = time.time()
        # Validate X-knock header if one is required:
        if self._knock is not None:
            x_knock = self.request.headers.get('X-knock', None)
            if x_knock != self._knock:
                self.set_status(401)
                self.write(b"Invalid knock\r\n")
                self.finish()
                log.info("Invalid knock")
            
    def shutdown_if_ready(self):
        """Shutdown if it's time to shutdown"""
        # If the resource has been retrieved all the times it's allowed:
        if self._allowed_gets > 0 and self._allowed_gets <= self._state['num_gets']:
            num_post_backs = self._state['num_posts']
            # If we're still waiting for post backs:
            if self._allow_post_backs and num_post_backs < self._allowed_gets:
                log.info("Waiting for {} more post backs from client".format(
                    self._allowed_gets - num_post_backs))
            else:
                # Shutdown:
                log.info("Served resource {} times. Done.".format(self._state['num_gets']))
                tornado.ioloop.IOLoop.current().stop()

class CurlbombResourceWrapperRequestHandler(tornado.web.RequestHandler):
    """Serve a script that wraps another curlbomb"""
    def initialize(self, curlbomb_command):
        self.__curlbomb_command = curlbomb_command
        
    def get(self):
        self.set_status(200)
        self.write(self.__curlbomb_command)
        self.finish()
                
class CurlbombResourceRequestHandler(CurlbombBaseRequestHandler):
    """Serve a file like resource a limited number of times.
    Allow response data to be posted back."""
    def get(self):
        if self._allowed_gets == 0 or self._state['num_gets'] < self._allowed_gets:
            # Client is allowed to get:
            self.set_status(200)
            self.add_header("Content-type", self._mime_type)
            self.write(self._resource.read())
            self._state['num_gets'] += 1
        else:
            # Client is not allowed to get any more:
            self.set_status(405)
            self.write(b"Client is not allowed to GET anymore\r\n")
            log.info("Resource denied (max gets reached) to: {}".format(
                self.request.remote_ip))
        self.finish()
        self._resource.seek(0)
        self.shutdown_if_ready()


@tornado.web.stream_request_body
class CurlbombStreamRequestHandler(CurlbombBaseRequestHandler):
    """Stream output of script from client back to the server"""
    def data_received(self, data):
        """Handle incoming PUT data"""
        if self._log_post_backs:
            print("[{}]: {}".format(self.request.headers.get('X-hostname', ''),
                                    data.decode("utf-8")), end="")

    def put(self):
        """Finish streamed PUT request"""
        self._state['num_posts_in_progress'] -= 1
        self._state['num_posts'] += 1
        self.finish()
        self.shutdown_if_ready()

    def post(self):
        self.put()
        
    def prepare(self):
        CurlbombBaseRequestHandler.prepare(self)
        if not self._allow_post_backs:
            self.set_status(405)
            self.write(b"This server is not configured to allow data upload\r\n")
            self.finish()
            return
        if (self._state['num_posts'] +
            self._state['num_posts_in_progress']) >= self._allowed_gets:
            self.set_status(403)
            self.write(b"Maximum number of posts reached\r\n")
            self.finish()
        self._state['num_posts_in_progress'] += 1
                
class ErrorRequestHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_status(404)
        self.write(b"404 Not Found\n")
        
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
        log.info("Creating ssh forward {} via {}".format(self.remote_forward, self.host))
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
                    log.info("SSH forward established")
                    return True
                time.sleep(0.1)
            return False
        except KeyboardInterrupt:
            self.kill()
    
    def kill(self):
        self._kill = True
        self.join()
        log.info("SSH connection closed: {}".format(self.host))

def get_curlbomb_command(settings, unwrapped=None):
    """Get the curlbomb command

    Inspects settings['unwrapped'] and returns the full curlbomb
    command if True. A wrapper script is returned in the default case.
    
    Alternatively, you can pass unwrapped=True to force getting the
    unwrapped script.
    """
    if (settings['unwrapped'] and unwrapped is not False) or unwrapped is True:
        # Get the full unwrapped command:
        if settings['require_knock']:
            if settings.get('require_knock_from_environment', False):
                # Don't output the actual knock code, but the shell variable name:
                k = "$KNOCK"
            else:
                k = settings['knock']
            if settings['http_fetcher'].startswith("wget"):
                knock = ' --header="X-knock: {}"'.format(k)
            else:
                knock = ' -H "X-knock: {}"'.format(k)
        else:
            knock = ""

        if settings['require_hostname_header']:
            if settings['http_fetcher'].startswith("wget"):
                hostname_header = ' --header="X-hostname: $(hostname)"'
            else:
                hostname_header = ' -H "X-hostname: $(hostname)"'
        else:
            hostname_header = ""

        if settings['client_logging'] or settings['receive_postbacks']:
            logger = " | tee"

            if settings['client_logging']:
                logger += "curlbomb.log"

            if settings['receive_postbacks']:
                callback_cmd=" >(curl -T - http{ssl}://{host}:{port}/s{knock}{hostname_header})"
                if settings['wget']:
                    callback_cmd = (
                        ' && wget -q -O - --post-data="wget post-back finished. '
                        'wget can\'t stream the client output like curl can though '
                        ':(\r\n" http{ssl}://{host}:{port}/s{knock}{hostname_header}')
                logger += callback_cmd.format(
                        ssl="s" if settings['ssl'] is not None else "",
                        host=settings['display_host'],
                        port=settings['display_port'],
                        knock=knock,
                        hostname_header=hostname_header
                    )
        else:
            logger = ""

        if settings['shell_command'] is None or settings['survey']:
            cmd = "{http_fetcher} http{ssl}://{host}:{port}/r{knock}{hostname_header}{logger}".\
                  format(
                      http_fetcher=settings['http_fetcher'],
                      ssl="s" if settings['ssl'] is not None else "",
                      host=settings['display_host'],
                      port=settings['display_port'],
                      knock=knock,
                      hostname_header=hostname_header,
                      logger=logger)
        else:
            cmd = "{shell_command} <({http_fetcher} http{ssl}://{host}:{port}/r{knock}"\
                  "{hostname_header}){logger}".format(
                      http_fetcher=settings['http_fetcher'],
                      shell_command=settings['shell_command'],
                      ssl="s" if settings['ssl'] is not None else "",
                      host=settings['display_host'],
                      port=settings['display_port'],
                      knock=knock,
                      hostname_header=hostname_header,
                      logger=logger)

        return cmd
    else:
        # Get the wrapped version:
        if settings['survey']:
            if settings['require_knock']:
                if settings['http_fetcher'].startswith("wget"):
                    knock_header = ' --header="X-knock: {}"'.format(settings['knock'])
                else:
                    knock_header = ' -H "X-knock: {}"'.format(settings['knock'])
            else:
                knock_header=''
            cmd = "{http_fetcher} http{ssl}://{host}:{port}/r" + knock_header
        else:
            cmd = "{knock}bash <({http_fetcher} http{ssl}://{host}:{port})"

        return cmd.format(
              http_fetcher=settings['http_fetcher'],
              ssl="s" if settings['ssl'] is not None else "",
              host=settings['display_host'],
              port=settings['display_port'],
              knock="KNOCK='{}' ".format(
                  settings['knock']) if settings['require_knock'] else ''
        )


def run_server(settings):
    settings['state'] = {'num_gets': 0, 'num_posts': 0, 'num_posts_in_progress': 0}
    curlbomb_args = dict(
        resource=settings['resource'],
        state=settings['state'],
        allowed_gets=settings['num_gets'],
        knock=settings['knock'],
        mime_type=settings['mime_type'],
        allow_post_backs=settings['receive_postbacks'],
        log_post_backs=settings['log_post_backs']
    )

    unwrapped_script = 'time '+get_curlbomb_command(settings, unwrapped=True)

    app = tornado.web.Application(
        [
            (r"/", CurlbombResourceWrapperRequestHandler,
             dict(curlbomb_command=unwrapped_script)),
            (r"/r", CurlbombResourceRequestHandler, curlbomb_args),
            (r"/s", CurlbombStreamRequestHandler, curlbomb_args)
        ], default_handler_class=ErrorRequestHandler
    )
    
    ## Load SSL certificate if specified:
    if settings['ssl'] is not None:
        with open(settings['ssl'], 'br') as cert_file:
            cert = cert_file.read()
            if cert.startswith(b'-----BEGIN PGP MESSAGE-----'):
                # Decrypt PGP encrypted certfile:
                log.info("Attempting SSL certificate decryption")
                with subprocess.Popen(
                        ['gpg','-d'], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
                    p.stdin.write(cert)
                    decrypted_cert, stderr = p.communicate()
                    # Log gpg info which includes identity used to decrypt cert:
                    log.info(stderr.decode("utf-8"))
                    if p.returncode != 0:
                        log.error("Could not load encrypted certificate")
                        sys.exit(1)
                    # Create temporary file to store decrypted cert.
                    # This isn't the most secure method I can think of,
                    # but I can't see another way as the low-level openssl
                    # api requires a file and will not accept a string
                    # or file like object.
                    with tempfile.NamedTemporaryFile('wb') as temp_cert:
                        temp_cert.write(decrypted_cert)
                        del decrypted_cert
                        # SSL with decrypted cert:
                        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        ssl_ctx.load_cert_chain(temp_cert.name)
                        httpd = app.listen(settings['port'],
                                           ssl_options=ssl_ctx)
            else:
                # SSL with plain text cert:
                httpd = app.listen(settings['port'],
                                   ssl_options=dict(certfile=settings['ssl']))
            log.info("SSL certificate loaded")
    else:
        # No SSL
        httpd = app.listen(settings['port'])

    ## Start SSH tunnel if requested:
    httpd.ssh_conn = None
    if settings['ssh']:
        httpd.ssh_conn = SSHRemoteForward(
            settings['ssh_host'], settings['ssh_forward'], settings['ssh_port'])
        httpd.ssh_conn.start()
        if not httpd.ssh_conn.wait_connected():
            log.error(httpd.ssh_conn.last_msg)
            sys.exit(1)

    cmd = get_curlbomb_command(settings)
    if not settings['quiet']:
        sys.stderr.write("Paste this command on the client:\n")
        sys.stderr.write("\n")
        sys.stderr.write("  {}\n".format(cmd))
        sys.stderr.write("\n")
            
    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.stop()
        if httpd.ssh_conn is not None:
            httpd.ssh_conn.kill()
        settings['resource'].close()

def argparser(formatter_class=argparse.HelpFormatter):
    parser = argparse.ArgumentParser(
        description='curlbomb is an HTTP server for serving one-time-use shell scripts',
        formatter_class=formatter_class)
    parser.add_argument('-k', '--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)")
    parser.add_argument('-n', '--num-gets', metavar="N",
                        help="Number of times to serve resource (default:1)",
                        type=int, default=1)
    parser.add_argument('-p', '--port',  help="TCP port number to use "
                        "(default:random available)",
                        default="random")
    parser.add_argument('-c', '--command', metavar="CMD",
                        help="The the shell command to curlbomb into "
                        "(default is to detect #!interpreter ie. the shebang)",
                        default="AUTO")
    parser.add_argument('-d','--domain', metavar="host[:port]",
                        help="Provide the domain and port to display "
                        "in the constructed URL. (example.com:8080)")
    parser.add_argument('-w', '--wget', 
                        help="Output wget command rather than curl",
                        action="store_true")
    parser.add_argument('-l','--log-posts', dest="log_post_backs", action="store_true",
                        help="Log client stdout to server stdout")
    parser.add_argument('-q', '--quiet', action="store_true",
                        help="Be more quiet. Don't print the curlbomb command")
    parser.add_argument('-v', '--verbose', action="store_true",
                        help="Be more verbose. Enables --log-posts and print INFO logging")
    parser.add_argument('--ssh', metavar="SSH_FORWARD",
                        help="Forward curlbomb through another host via SSH - "
                        "[user@]host[:ssh_port][:http_port]",
                        default=None)
    parser.add_argument('--ssl', metavar="CERTIFICATE",
                        help="Use SSL with the given certificate file "
                        "(optionally PGP encrypted)")
    parser.add_argument('--survey', help="Just a survey mission, no bomb run "
                        "(just get the script, don't run it)", action="store_true")
    parser.add_argument('--unwrapped', help="Get the unwrapped version of the curlbomb (1 less server request, but longer command)", action="store_true")
    parser.add_argument('--disable-postback', help="Do not post client output back to the server", action="store_true")
    parser.add_argument('--client-logging', dest="client_logging",
                        help="Enable client execution log (curlbomb.log on client)",
                        action="store_true")
    parser.add_argument('--mime-type', help="The content type to serve",
                        default="text/plain")
    parser.add_argument('--version', action="version", version=get_version())
    parser.add_argument('resource', metavar="FILE", nargs='?', default=sys.stdin,
                        help="File to serve (or don't specify for stdin)")
    return parser
                
def parse_args(args=None):
    """Parse args and set other settings based on them
    
    Return a new dictionary containing all args and settings
    """
    parser = argparser()    
    args = parser.parse_args(args)

    settings = {
        'receive_postbacks': True,
        'shell_command': args.command,
        'http_fetcher': 'curl -LSs',
        'mime_type': args.mime_type,
        'require_hostname_header': True,
        'log_post_backs': args.log_post_backs,
        'ssl': args.ssl,
        'num_gets': args.num_gets,
        'require_knock': not args.disable_knock,
        'knock': None,
        'verbose': args.verbose,
        'survey': args.survey,
        'ssh': args.ssh,
        'quiet': args.quiet and not args.verbose,
        'client_logging': args.client_logging,
        'require_knock_from_environment': True,
        'wget': args.wget,
        'unwrapped': args.unwrapped
    }
    
    if args.verbose:
        log.setLevel(level=logging.INFO)
        settings['log_post_backs'] = True
        logging.getLogger('tornado.access').setLevel(level=logging.INFO)
        
    if args.resource == sys.stdin and sys.stdin.isatty():
        parser.print_help()
        sys.stderr.write("\nYou must specify a file or pipe one to this command's stdin\n")
        sys.exit(1)
    if args.resource == sys.stdin or args.resource == '-':
        settings['resource'] = BytesIO(sys.stdin.buffer.read())
    else:
        settings['resource'] = open(args.resource, 'br')

    if settings['require_knock']:
        settings['knock'] = base64.b64encode(bytes(random.sample(range(256), 12)),
                                             altchars=b'_.').decode("utf-8")

    if settings['survey']:
        # Don't recieve post backs in survey mode:
        settings['receive_postbacks'] = False
        settings['client_logging'] = False

    if args.disable_postback:
        settings['receive_postbacks'] = False
        
    if settings['unwrapped']:
        # Output the unrwapped version of the curlbomb Without this
        # setting, curlbomb usually outputs a url that retrieves a
        # wrapper script that wraps the longer more complicated client
        # command. This will output this unrwapped version instead.
        settings['require_knock_from_environment'] = False
        
    #Detect if the input has a shebang so we can detect the shell command to display
    if args.command == "AUTO":
        line = settings['resource'].readline(500)
        settings['resource'].seek(0)
        if line.startswith(b'#!'):
            settings['shell_command'] = line[2:].decode("utf-8").rstrip()
        else:
            settings['shell_command'] = "bash"

    if args.wget:
        settings['http_fetcher'] = "wget -q -O -"
        if args.log_post_backs:
            print("wget can't stream the client output, so --log-posts is not "
                  "supported in wget mode")
            sys.exit(1)

    if args.port == "random":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('',0))
        settings['port'] = s.getsockname()[1]
        s.close()
    else:
        settings['port'] = int(args.port)

    settings['display_host'] = socket.gethostbyname(socket.gethostname())
    settings['display_port'] = settings['port']

    if settings['ssh']:
        ssh_parts = settings['ssh'].split(":")
        ssh_host = ssh_parts[0]
        ssh_port = 22
        http_port = settings['port']
        if len(ssh_parts) == 3:
            ssh_port = ssh_parts[1]
            http_port = ssh_parts[2]
        elif len(ssh_parts) == 2:
            http_port = ssh_parts[1]
        settings['ssh_forward'] = "0.0.0.0:{http_port}:localhost:{port}".format(
            port=settings['port'], http_port=http_port)
        settings['ssh_host'] = ssh_host
        settings['ssh_port'] = ssh_port
        settings['display_port'] = http_port
        if '@' in ssh_host:
            settings['ssh_user'], settings['display_host'] = ssh_host.split('@')
        else:
            settings['display_host'] = ssh_host

    if args.domain:
        # Override displayed host:port
        parts = args.domain.split(":")
        settings['display_host'] = parts[0]
        if len(parts) > 1:
            settings['display_port'] = parts[1]

    return settings

def main():
    settings = parse_args()
    run_server(settings)
    
if __name__ == "__main__":
    main()
