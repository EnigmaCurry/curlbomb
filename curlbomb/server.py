import sys
import os
import time
import logging
import tempfile
import subprocess
import _thread
import traceback

import tornado.web
import tornado.ioloop
import tornado.gen
import requests
import psutil

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
                log.info("Served resource {} times. Done. Waiting for network buffers to clear".format(self._state['num_gets']))
                # Query psutil for ongoing socket connections that we don't want to kill yet:
                proc = psutil.Process(os.getpid())
                while True:
                    for conn in proc.connections():
                        if conn.status == 'ESTABLISHED':
                            time.sleep(1)
                            break
                    else:
                        break    
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

    def head(self):
        """Allow head requests, does not count towards num_gets and does not require a knock"""
        pass
                
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

    def head(self):
        """Allow head requests, does not count towards num_gets and does not require a knock"""
        pass


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

    global httpd
    httpd = app.listen(
        settings['port'],
        ssl_options=settings['ssl_context'],
        max_buffer_size=1024E9)

    ## Start SSH tunnel if requested:
    httpd.ssh_conn = None
    if settings['ssh']:
        if settings['ssl'] is False:
            log.warn("Using --ssh without --ssl is probably not a great idea")
        httpd.ssh_conn = SSHRemoteForward(
            settings['ssh_host'], settings['ssh_forward'], settings['ssh_port'])
        httpd.ssh_conn.start()
        if not httpd.ssh_conn.wait_connected():
            log.error(httpd.ssh_conn.last_msg)
            sys.exit(1)

    cmd = settings['get_curlbomb_command'](settings)
    if not settings['quiet']:
        if settings['stdout'].isatty():
            sys.stderr.write("Paste this command on the client:\n\n")
            sys.stderr.write("  {}\n\n".format(cmd))
            if settings['passphrase']:
                sys.stderr.write("Client passphrase: {}\n\n".format(settings['passphrase']))
        else:
            sys.stderr.write("{}\n".format(cmd))

    # Disable port forward checker for now. Good idea, but it doesn't work reliably.
    # 
    # if settings['ssh'] and not settings['args'].domain:
    #     "Check the SSH forward works"
    #     def check_port_forward(timeout=5):
    #         time.sleep(5)
    #         try:
    #             url = "http{ssl}://{host}:{port}".format(
    #                 ssl="s" if settings['ssl'] is not False else "",
    #                 host=settings['display_host'],
    #                 port=settings['display_port'])
    #             log.info("Testing port forward is functioning properly - {}".format(url))
    #             r = requests.head(url, timeout=timeout)
    #         except (requests.ConnectionError, requests.exceptions.ReadTimeout):
    #             log.warn("Could not contact server throuh SSH forward. You may need to check your sshd_config and enable 'GatwayPorts clientspecified'")
    #     _thread.start_new_thread(check_port_forward, ())

    try:
        log.debug("server ready on local port {}".format(settings['port']))
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        if settings['verbose']:
            traceback.print_exc()
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
