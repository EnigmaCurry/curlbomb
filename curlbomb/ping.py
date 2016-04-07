from io import BytesIO
from collections import OrderedDict
import urllib
import shlex
import subprocess
import logging

log = logging.getLogger('curlbomb.ping')

def prepare(args, settings, parser):
    settings['resource'] = BytesIO(b'')
    settings['survey'] = True
    settings['receive_postbacks'] = False
    
    def get_ping_command(settings, unwrapped=None):
        params = OrderedDict()
        if settings['require_knock']:
            params['knock'] = settings['knock']
        if args.message:
            params['message'] = args.message
        if args.return_code:
            params['return'] = args.return_code
        
        return "curl -LSs 'http{ssl}://{host}:{port}/r{query_params}'".format(
            ssl="s" if settings['ssl'] is not None else "",
            host=settings['display_host'],
            port=settings['display_port'],
            query_params="?"+urllib.parse.urlencode(
                params) if len(params)>0 else ""
            )
    settings['get_curlbomb_command'] = get_ping_command
    
    def get_callback(request):
        """Callback that server runs on ping from client

        request - the tornado.web.HTTPRequest from the client
        """
        # Handle return code parameter:
        return_code = request.arguments.get('return', [b"0"])[0]
        message = request.arguments.get('message', [b""])[0].decode("utf-8")
        try:
            return_code = int(return_code)
        except ValueError:
            log.warn("Client ping specified non-integer return code: {}".format(
                return_code))
            return_code = 0
        # Only change the return code if it's not 0.
        # This way multiple clients can ping and
        # all must be successful to return 0:
        if return_code != 0 and not args.return_success:
            settings['return_code'] = return_code

        # Handle notification command (-c)
        if args.command is not None:
            command = args.command.format(
                return_code=return_code, message='"{}"'.format(message.replace(r'"',r'\"')))
            log.info("Running notification command: {}".format(shlex.split(command)))
            out = subprocess.Popen(shlex.split(command),
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT).communicate()[0]
            log.info("notification out: {}".format(out))

        # Handle desktop notification (-n)
        if args.notify:
            try:
                import notify2
                notify2.init("curlbomb")
            except ImportError:
                log.error("Desktop notifications are disabled. Please install "
                          "python-notify2 package to enable.")
            else:
                notify2.Notification("Ping", message).show()
                
    settings['get_callback'] = get_callback
