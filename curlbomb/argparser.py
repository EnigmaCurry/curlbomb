import sys
import argparse

from . import run
from . import get
from . import put
from . import ping

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

    
    run.add_parser(subparsers)
    put.add_parser(subparsers)
    get.add_parser(subparsers)
    ping.add_parser(subparsers)
    
    return parser


