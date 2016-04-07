import sys
import argparse

from . import run
from . import get
from . import put
from . import ping

def return_code(x):
    x = int(x)
    if x<0 or x>255:
        raise ValueError("valid range is 0-255")
    return x

def get_version():
    import pkg_resources
    try:
        pkg = pkg_resources.get_distribution('curlbomb')
    except pkg_resources.DistributionNotFound:
        return 'DEV'
    if __file__.startswith(pkg.location):
        return pkg.version
    return 'DEV'

def argparser(formatter_class=argparse.HelpFormatter):
    parser = argparse.ArgumentParser(
        description='curlbomb is an HTTP server for serving one-time-use shell scripts',
        formatter_class=formatter_class)
    subparsers = parser.add_subparsers()
    
    parser.add_argument('-n', '--num-gets', metavar="N",
                        help="Number of times to serve resource (default:1)",
                        type=int, default=1)
    parser.add_argument('-p', '--port',  help="TCP port number to use "
                        "(default:random available)",
                        default="random")
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
    parser.add_argument('--unwrapped',
                        help="Get the unwrapped version of the curlbomb "
                        "(1 less server request, but longer command)", action="store_true")
    parser.add_argument('--disable-postback',
                        help="Do not post client output back to the server",
                        action="store_true")
    parser.add_argument('--client-logging', dest="client_logging",
                        help="Enable client execution log (curlbomb.log on client)",
                        action="store_true")
    parser.add_argument('--client-quiet', dest="client_quiet",
                        help="Quiet the output on the client",
                        action="store_true")
    parser.add_argument('--mime-type', help="The content type to serve",
                        default="text/plain")
    parser.add_argument('--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)")
    parser.add_argument('--version', action="version", version=get_version())

    run_parser = subparsers.add_parser('run', help="Run a local script on the client")
    run_parser.add_argument('-c', '--command', metavar="COMMAND",
                            help="The the shell command to curlbomb into "
                            "(default is to detect #!interpreter ie. the shebang)",
                            default=None)
    run_parser.add_argument('resource', metavar="SCRIPT", nargs='?', default=sys.stdin)
    run_parser.set_defaults(prepare_command=run.prepare)
    
    put_parser = subparsers.add_parser(
        'put', help='Copy local files or directories to the client')
    put_parser.add_argument('source', metavar="SOURCE", nargs=1,
                            help="Local path to copy (or put glob in quotes)")
    put_parser.add_argument('dest', metavar="DEST", nargs='?',
                            help="Remote directory to copy to")
    put_parser.add_argument('--exclude', metavar="PATTERN", action='append',
                            help="Exclude files matching PATTERN, "
                            "a glob(3)-style wildcard pattern", default=[])
    put_parser.set_defaults(prepare_command=put.prepare)

    get_parser = subparsers.add_parser(
        'get', help='Copy remote files or directories to the server')
    get_parser.add_argument('source', metavar="SOURCE", nargs=1,
                            help="Remote path to copy (or put glob in quotes)")
    get_parser.add_argument('dest', metavar="DEST", nargs='?',
                            help="Local directory to copy to")
    get_parser.add_argument('--exclude', metavar="PATTERN", action='append',
                            help="Exclude files matching PATTERN, "
                            "a glob(3)-style wildcard pattern", default=[])
    get_parser.set_defaults(prepare_command=get.prepare)

    ping_parser = subparsers.add_parser(
        'ping', help="Waits for client(s) to make a request, containing optional "
        "message and return parameters. Returns 0 or the last non-zero return "
        "parameter received from client(s).")
    ping_parser.add_argument('-m', '--message',
                             help="Adds message parameter to ping request")
    ping_parser.add_argument('-r', '--return', dest='return_code',
                             type=return_code,
                             help="Adds return parameter to ping request")
    ping_parser.add_argument(
        '--return-success', action='store_true',
        help="Always return 0 regardless of the 'return' parameter the "
        "client(s) sends back")
    ping_parser.add_argument('-c','--command', help="Command to run on ping. "
                             "string formatters include: {return_code}, {message} "
                             "(don't use quotes around them)")
    ping_parser.add_argument('-n', '--notify', action="store_true",
                             help="Notify of ping via libnotify (python-notify2 package)")
    ping_parser.set_defaults(prepare_command=ping.prepare)
    
    return parser


