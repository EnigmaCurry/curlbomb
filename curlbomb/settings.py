import sys
import logging
import socket
import base64
import random

from . import run

log = logging.getLogger('curlbomb.settings')

from .argparser import argparser

def get_curlbomb_command(settings, unwrapped=None):
    """Get the curlbomb command

    Inspects settings['unwrapped'] and returns the full curlbomb
    command if True. A wrapper script is returned in the default case.
    
    Alternatively, you can pass unwrapped=True to force getting the
    unwrapped script.
    """
    if (settings['unwrapped'] and unwrapped is not False) or unwrapped is True:
        # Get the full unwrapped command:
        knock = ""
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

        hostname_header = ""
        if settings['require_hostname_header']:
            if settings['http_fetcher'].startswith("wget"):
                hostname_header = ' --header="X-hostname: $(hostname)"'
            else:
                hostname_header = ' -H "X-hostname: $(hostname)"'

        logger = ""
        if settings['client_logging']:
            logger = " | tee curlbomb.log"

        if settings['receive_postbacks']:
            callback_cmd="curl -T - http{ssl}://{host}:{port}/s{knock}{hostname_header}"
            if settings['client_quiet']:
                callback_cmd = " | " + callback_cmd
            else:
                callback_cmd = " | tee >({cmd})".format(cmd=callback_cmd)
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

    
def get_settings(args=None, override_defaults={}):
    """Parse args and set other settings based on them

    Default settings can be overriden by passing in a dictionary
    
    Return a new dictionary containing all args and settings
    """
    # Parse the arguments:
    parser = argparser()
    args = parser.parse_args(args)
        
    settings = {
        # Instruct client to post stdout back to the server:
        'receive_postbacks': True,
        # Run client script with this shell interpreter:
        'shell_command': 'bash',
        # Client fetches URL resources with this command:
        'http_fetcher': 'curl -LSs',
        # Mime type to serve resource as:
        'mime_type': args.mime_type,
        # Client should send it's hostname in the request header:
        'require_hostname_header': True,
        # Log client stdout to server stdout:
        'log_post_backs': args.log_post_backs,
        # Enable TLS
        'ssl': args.ssl,
        # Total number of allowed HTTP gets on resource:
        'num_gets': args.num_gets,
        # Require X-knock header:
        'require_knock': not args.disable_knock,
        # The current knock:
        'knock': None,
        # Server verbose flag
        'verbose': args.verbose,
        # Print curl command without shell_command
        'survey': args.survey,
        # SSH tunnel
        'ssh': args.ssh,
        # Server quiet flag
        'quiet': args.quiet and not args.verbose,
        # Log stdout on client:
        'client_logging': args.client_logging,
        # Client quiet flag
        'client_quiet': args.client_quiet,
        # Popen object processing log_post_backs
        'log_process': None,
        # File to receive log_post_backs:
        'log_file': None,
        # Don't print knock in wrapped curlbomb command:
        'require_knock_from_environment': True,
        # Client should use wget instead of curl
        'wget': args.wget,
        # Don't wrap curlbomb 
        'unwrapped': args.unwrapped,
        # Use alternative stdin, only used in tests
        'stdin': sys.stdin,
        # Use alternative stdout, only used in tests
        'stdout': sys.stdout,
        # Output how long the command takes:
        'time_command': False,
        # Function to get curlbomb command given settings:
        'get_curlbomb_command': get_curlbomb_command
    }
    settings.update(override_defaults)
    
    if args.verbose:
        logging.getLogger('curlbomb').setLevel(level=logging.INFO)
        settings['log_post_backs'] = True
        logging.getLogger('tornado.access').setLevel(level=logging.INFO)
        
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

    if not settings['stdout'].isatty() and not settings['quiet']:
        # Imply we want log-posts if we pipe to a non-tty:
        settings['log_post_backs'] = True

    try:
        prepare_cmd = args.prepare_command
    except AttributeError:
        # No sub-command specified, default to run command with stdin
        args.command = None
        args.resource = settings['stdin']
        prepare_cmd = run.prepare
    prepare_cmd(args, settings)

    return settings
