import sys
import logging
import socket
import base64
import random
import shlex

from .subcommands import run
from . import tls
from . import gpg

log = logging.getLogger('curlbomb.settings')

from .argparser import argparser, get_arg_value

def random_passphrase(length):
    return base64.b64encode(bytes(random.sample(range(256), length)),
                            altchars=b'_.').decode("utf-8")[:length]

def get_curlbomb_command(settings, unwrapped=None):
    """Get the curlbomb command

    Inspects settings['unwrapped'] and returns the full curlbomb
    command if True. A wrapper script is returned in the default case.
    
    Alternatively, you can pass unwrapped=True to force getting the
    unwrapped script.
    """
    # Pin tls cert to client command if we are using curl, --ssl, and --pin
    pin_settings=""
    if settings['http_fetcher'].startswith("curl") and \
       settings['ssl'] is not False and settings['pin'] is True:
        pin_settings = " -k --pinnedpubkey 'sha256//{}'".format(settings['ssl_hash'])

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

        url = "http{ssl}://{host}:{port}/r{knock}{hostname_header}".format(
            ssl="s" if settings['ssl'] is not False else "",
            host=settings['display_host'],
            port=settings['display_port'],
            knock=knock,
            hostname_header=hostname_header
        )
        stream_url = "http{ssl}://{host}:{port}/s{knock}{hostname_header}".format(
            ssl="s" if settings['ssl'] is not False else "",
            host=settings['display_host'],
            port=settings['display_port'],
            knock=knock,
            hostname_header=hostname_header
        )

        decrypter = ""
        if settings['client_decrypt']:
            decrypter = " | gpg -d"

        logger = ""
        if settings['client_logging']:
            logger = " | tee curlbomb.log"

        if settings['receive_postbacks']:
            callback_cmd="curl{pin_settings} -T - {stream_url}"
            if settings['client_quiet']:
                callback_cmd = " | " + callback_cmd
            else:
                callback_cmd = " | tee >({cmd})".format(cmd=callback_cmd)
            if settings['wget']:
                callback_cmd = (
                    ' && wget -q -O - --post-data="wget post-back finished. '
                    'wget can\'t stream the client output like curl can though '
                    ':(\r\n" {stream_url}')
            logger += callback_cmd.format(
                stream_url=stream_url,
                pin_settings=pin_settings
                )
        
        if settings['shell_command'] is None or settings['survey']:
            cmd = "{http_fetcher}{pin_settings} {url}{decrypter}{logger}".\
                  format(
                      http_fetcher=settings['http_fetcher'],
                      url=url,
                      pin_settings=pin_settings,
                      decrypter=decrypter,
                      logger=logger)
        else:
            cmd = "{shell_command} <({http_fetcher}{pin_settings} {url}{decrypter}){logger}"
            if settings['pipe_to_shell_command']:
                # If we don't care about receiving client output, pipe
                # it rather than redirecting. This is needed for
                # interactive scripts:
                cmd = "{http_fetcher}{pin_settings} {url} | {shell_command}{logger}"
            cmd = cmd.format(
                shell_command=settings['shell_command'],
                http_fetcher=settings['http_fetcher'],
                pin_settings=pin_settings,
                url=url,
                decrypter=decrypter,
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
            cmd = "{http_fetcher}{pin_settings} http{ssl}://{host}:{port}/r" + knock_header
        else:
            cmd = "{knock}bash <({http_fetcher}{pin_settings} http{ssl}://{host}:{port})"

        return cmd.format(
            http_fetcher=settings['http_fetcher'],
            ssl="s" if settings['ssl'] is not False else "",
            host=settings['display_host'],
            port=settings['display_port'],
            pin_settings=pin_settings,
            knock="KNOCK={} ".format(
                shlex.quote(settings['knock'])) if settings['require_knock'] else ''
        )

    
def get_settings(args=None, override_defaults={}):
    """Parse args and set other settings based on them

    Default settings can be overriden by passing in a dictionary
    
    Return a new dictionary containing all args and settings
    """
    # Parse the arguments:
    parser = argparser()
    args = parser.parse_args(args)

    def get_value(name, default=None):
        return get_arg_value(args, name, default)
    
    settings = {
        # Store args object:
        'args': args,
        # Log file:
        'log_file': get_value('log_file'),
        # Instruct client to post stdout back to the server:
        'receive_postbacks': get_value('log_post_backs', False),
        # Run client script with this shell interpreter:
        'shell_command': 'bash',
        # Client fetches URL resources with this command:
        'http_fetcher': 'curl -LSs',
        # Mime type to serve resource as:
        'mime_type': get_value('mime_type', 'text/plain'),
        # Client should send it's hostname in the request header:
        'require_hostname_header': False,
        # Log client stdout to server stdout:
        'log_post_backs': get_value('log_post_backs', False),
        # Enable TLS - 
        'ssl': True if get_value('ssl') is not None else False,
        # SSL Certificate path
        'ssl_path': get_value('ssl') if get_value('ssl') is not "-" else None,
        # ssl context passed to server
        'ssl_context': None,
        # Enable SSL certificate pinning in client command:
        'pin': get_value('pin', False),
        # Total number of allowed HTTP gets on resource:
        'num_gets': get_value("num_gets", 1),
        # Require X-knock header:
        'require_knock': not get_value("disable_knock", False),
        # The current knock:
        'knock': get_value("knock"),
        # Server verbose flag
        'verbose': get_value("verbose") or get_value("debug"),
        # Server debug flag
        'debug': get_value("debug", False),
        # Print curl command without shell_command
        'survey': get_value("survey", False),
        # SSH tunnel
        'ssh': get_value("ssh"),
        # Server quiet flag
        'quiet': get_value("quiet") and not get_value("verbose"),
        # Log stdout on client:
        'client_logging': get_value("client_logging", False),
        # Client quiet flag
        'client_quiet': get_value("client_quiet", False),
        # Client decryption:
        'client_decrypt': get_value("encrypt") or get_value("passphrase") or get_value("encrypt_to"),
        # Server encryption (random_passphrase, user_passphrase, recipient):
        'encryption_type': "user_passphrase" if get_value("passphrase") else "recipient" if \
            get_value("encrypt_to") else "random_passphrase" if get_value("encrypt") else None,
        # the passphrase that was generated or supplied by the user:
        'passphrase': None,
        # Popen object processing log_post_backs
        'log_process': None,
        # File to receive log_post_backs:
        'postback_log_file': None,
        # Don't print knock in wrapped curlbomb command:
        'require_knock_from_environment': True,
        # Client should use wget instead of curl
        'wget': get_value("wget"),
        # Don't wrap curlbomb 
        'unwrapped': get_value("unwrapped", False),
        # Use alternative stdin, only used in tests
        'stdin': sys.stdin,
        # Use alternative stdout, only used in tests
        'stdout': sys.stdout,
        # Output how long the command takes:
        'time_command': False,
        # Function to get curlbomb command given settings:
        'get_curlbomb_command': get_curlbomb_command,
        # Normally we do process substituition, but we can do a regular pipe as well:
        'pipe_to_shell_command': get_value("pipe", False)
    }
    settings.update(override_defaults)

    if settings['log_file']:
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.basicConfig(filename=settings['log_file'], level=logging.WARN)
    
    if settings['verbose']:
        logging.getLogger('curlbomb').setLevel(level=logging.INFO)
        logging.getLogger('tornado.access').setLevel(level=logging.INFO)

    if settings['debug']:
        settings['verbose'] = True
        logging.getLogger('curlbomb').setLevel(level=logging.DEBUG)
        logging.getLogger('tornado.access').setLevel(level=logging.DEBUG)
        
    if settings['require_knock'] and not settings['knock']:
        settings['knock'] = random_passphrase(12)
        
    if settings['survey']:
        # Don't recieve post backs in survey mode:
        settings['receive_postbacks'] = False
        settings['client_logging'] = False

    if get_value("disable_postback"):
        log.error("--disable-postback and -1 are no longer valid options. If you were using it for interactive script support, use --pipe.")
        sys.exit(1)
        
    if settings['unwrapped']:
        # Output the unrwapped version of the curlbomb Without this
        # setting, curlbomb usually outputs a url that retrieves a
        # wrapper script that wraps the longer more complicated client
        # command. This will output this unrwapped version instead.
        settings['require_knock_from_environment'] = False

    if settings["pin"] and not settings['ssl']:
        print("--pin requires --ssl")
        sys.exit(1)
    if settings['ssl'] and settings['ssl_path'] == None:
        # Auto pin ssl cert if ssl cert is auto-generated
        settings['pin'] = True

    if settings['encryption_type'] == 'user_passphrase':
        if get_value("encrypt_to"):
            print("--passphrase and --encrypt-to options are incompatible with each other.")
            sys.exit(1)
        if not settings['passphrase']:
            settings['passphrase'] = input("Enter passphrase to encrypt resource: ")
        if len(settings['passphrase']) == 0:
            log.error("Passphrase cannot be blank")
            sys.exit(1)
    elif settings['encryption_type'] == 'random_passphrase':
        settings['passphrase'] = random_passphrase(25)

    if settings['wget']:
        settings['http_fetcher'] = "wget -q -O -"
        if settings['log_post_backs']:
            print("wget can't stream the client output, so --log-posts is not "
                  "supported in wget mode")
            sys.exit(1)
        if settings['pin']:
            print("SSL certificate pinning only works in curl mode")
            sys.exit(1)

    if get_value("port") is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('',0))
        settings['port'] = s.getsockname()[1]
        s.close()
    else:
        settings['port'] = int(get_value("port"))

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

    if get_value("domain"):
        # Override displayed host:port
        parts = get_value("domain").split(":")
        settings['display_host'] = parts[0]
        if len(parts) > 1:
            settings['display_port'] = parts[1]

    if settings['ssl'] is not False:
        settings['ssl_context'] = tls.get_ssl_context_from_settings(settings)
    
    try:
        prepare_cmd = args.prepare_command
        try:
            subcommand = args.subcommand
        except AttributeError:
            log.error("Subparser does not specify it's own name")
            sys.exit(1)
    except AttributeError:
        # No sub-command specified, default to run command with stdin
        args.subcommand = "run"
        args.command = None
        args.script_hash = None
        args.signature = None
        args.resource = settings['stdin']
        prepare_cmd = run.prepare
    prepare_cmd(args, settings, parser)

    # Encrypt the resource if required:
    if settings['encryption_type'] in ('user_passphrase', 'random_passphrase'):
        settings['resource'] = gpg.encrypt_resource_symmetric(settings['resource'], settings['passphrase'])
    elif settings['encryption_type'] == 'recipient':
        settings['resource'] = gpg.encrypt_resource_to_recipients(settings['resource'], get_value("encrypt_to"))


    return settings
