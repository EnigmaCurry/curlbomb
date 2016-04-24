import sys
import time
import logging
import ssl
import tempfile
import subprocess

import tornado.web
import tornado.ioloop
import tornado.gen

from .ssh import SSHRemoteForward

log = logging.getLogger('curlbomb.server')


class CurlbombBaseRequestHandler(tornado.web.RequestHandler):
    """Base RequestHandler

      Implementations:
       - CurlbombResourceRequestHandler 
       - CurlbombStreamRequestHandler
    """
    
    def initialize(self, resource, state, allowed_gets=1, knock=None,
                   mime_type='text/plain', allow_post_backs=False,
                   log_post_backs=False, log_file=None, get_callback=None):
        """Arguments:
        
          resource         - A file like object to serve the contents of
          state            - State dictionary to maintain across requests
          allowed_gets     - Number of gets allowed before quiting
          knock            - The required X-knock header the client must send, or None
          mime_type        - The mime type the server should declare the content as
          allow_post_backs - Allow client to post data back to the server. 
                             Delays server termination until post_backs == allowed_gets
          log_post_backs   - Log post backs to stdout
          log_file         - Log post backs to file
          get_callback     - callback to run when get is finished, passes request
          *args            - The rest of the RequestHandler args
          **kwargs         - The rest of the RequestHandler kwargs
        """
        self._resource = resource
        self._allowed_gets = allowed_gets
        self._knock = knock
        self._mime_type = mime_type
        self._allow_post_backs = allow_post_backs
        self._get_callback = get_callback
        self._log_post_backs = log_post_backs
        self._log_file = log_file
        
        self._state = state
                
    def prepare(self):
        self.request.start_time = time.time()
        # Validate X-knock header if one is required:
        if self._knock is not None:
            x_knock = self.get_argument(
                'knock', self.request.headers.get('X-knock', None))
            if x_knock != self._knock:
                log.info("Invalid knock")
                raise tornado.web.HTTPError(401, 'Invalid knock')
    
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

    def write_error(self, status_code, **kwargs):
        try:
            log_message = kwargs.get('exc_info')[1].log_message
        except (TypeError, AttributeError, IndexError):
            log_message = 'unknown reason'
        self.finish(log_message+'\r\n')

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
            log.info("Resource denied (max gets reached) to: {}".format(
                self.request.remote_ip))
            raise tornado.web.HTTPError(405, 'Client is not allowed to GET anymore')
        self.finish()
        if self._state['num_gets'] < self._allowed_gets or self._allowed_gets == 0:
            self._resource.seek(0)
        if self._get_callback is not None:
            self._get_callback(self.request)
        self.shutdown_if_ready()

@tornado.web.stream_request_body
class CurlbombStreamRequestHandler(CurlbombBaseRequestHandler):
    """Stream output of script from client back to the server"""    
    def data_received(self, data):
        """Handle incoming PUT data"""
        if self._log_post_backs:
            sys.stdout.buffer.write(data)
        if self._log_file:
            self._log_file.write(data)
            self._log_file.flush()

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
        log.info("Stream prepare")
        if not self._allow_post_backs:
            raise tornado.web.HTTPError(405, 'This server is not configured to allow data upload')
        if (self._state['num_posts'] +
            self._state['num_posts_in_progress']) >= self._allowed_gets and self._allowed_gets != 0:
            raise tornado.web.HTTPError(403, 'Maximum number of posts reached')
        self._state['num_posts_in_progress'] += 1
                
class ErrorRequestHandler(tornado.web.RequestHandler):
    def get(self):
        raise tornado.web.HTTPError(404, 'Not Found')



def run_server(settings):
    settings['state'] = {'num_gets': 0, 'num_posts': 0, 'num_posts_in_progress': 0}
    curlbomb_args = dict(
        resource=settings['resource'],
        state=settings['state'],
        allowed_gets=settings['num_gets'],
        knock=settings['knock'],
        mime_type=settings['mime_type'],
        allow_post_backs=settings['receive_postbacks'],
        log_post_backs=settings['log_post_backs'],
        log_file=settings['log_file'],
        get_callback=settings.get('get_callback', None)
    )

    unwrapped_script = settings['get_curlbomb_command'](settings, unwrapped=True)
    if not settings['client_quiet'] and settings['time_command']:
        unwrapped_script = "time "+unwrapped_script

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
        httpd = app.listen(settings['port'], max_buffer_size=1024E9)

    ## Start SSH tunnel if requested:
    httpd.ssh_conn = None
    if settings['ssh']:
        httpd.ssh_conn = SSHRemoteForward(
            settings['ssh_host'], settings['ssh_forward'], settings['ssh_port'])
        httpd.ssh_conn.start()
        if not httpd.ssh_conn.wait_connected():
            log.error(httpd.ssh_conn.last_msg)
            sys.exit(1)

    cmd = settings['get_curlbomb_command'](settings)
    if not settings['quiet']:
        if settings['stdout'].isatty():
            sys.stderr.write("Paste this command on the client:\n")
            sys.stderr.write("\n")
            sys.stderr.write("  {}\n".format(cmd))
            sys.stderr.write("\n")
        else:
            sys.stderr.write("{}\n".format(cmd))
            
    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.stop()
        if httpd.ssh_conn is not None:
            httpd.ssh_conn.kill()
        settings['resource'].close()
        if settings['log_process']:
            settings['log_file'].close()
            settings['log_process'].wait()
            log.info("run_server done")

    return settings.get('return_code', 0)
