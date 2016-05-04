import sys
import argparse
import os

from . import run
from . import get
from . import put
from . import ping
from . import ssh_copy_id

def get_version(include_path=False):
    import pkg_resources
    path = os.path.split(__file__)[0]
    try:
        pkg = pkg_resources.get_distribution('curlbomb')
    except pkg_resources.DistributionNotFound:
        return 'DEV' + ( " - {}".format(path) if include_path else "")
    if __file__.startswith(pkg.location):
        return pkg.version + ( " - {}".format(path) if include_path else "")
    return 'DEV' + ( " - {}".format(path) if include_path else "")

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
                        "(optionally PGP encrypted.) CERTIFICATE may be specified as a "
                        "single - to generate a new self-signed certificate and to turn "
                        "on --pin", default=False)
    parser.add_argument('--pin', help="Pin the SSL certificate hash into the client "
                        "command to force curl to use our certificate"
                        " (requires --ssl)", action="store_true")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt resource with GPG before serving. Will use a randomly generated "
                        "symmetric passphrase unless --encrypt-to or --passphrase is specified.")
    parser.add_argument("--encrypt-to", action="append", metavar="GPG_ID", help="Encrypt with the "
                        "public key specified instead of a passphrase. Can be specified multiple times.")
    parser.add_argument("--passphrase", action="store_true",
                        help="Ask for a symmetric passphrase to encrypt with instead of a random one.")
    parser.add_argument('--survey', help="Just a survey mission, no bomb run "
                        "(just get the script, don't run it)", action="store_true")
    parser.add_argument('--unwrapped',
                        help="Get the unwrapped version of the curlbomb "
                        "(1 less server request, but longer command)", action="store_true")
    parser.add_argument('--client-logging', dest="client_logging",
                        help="Enable client execution log (curlbomb.log on client)",
                        action="store_true")
    parser.add_argument('--client-quiet', dest="client_quiet",
                        help="Quiet the output on the client",
                        action="store_true")
    parser.add_argument('--mime-type', help="The content type to serve",
                        default="text/plain")
    parser.add_argument('--pipe', help="Pipe to shell command rather than doing process substitution. "
                        "This is necessary for most interactive scripts.",
                        action="store_true")
    parser.add_argument('--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)")
    parser.add_argument('--knock', help="Use a specific knock rather than random",
                        default=None)
    parser.add_argument('--debug', action="store_true",
                        # Be really verbose, turn on debug logging
                        help=argparse.SUPPRESS)
    # Old disabled method for disabling postback logging:
    # Now this just outputs an error if the user uses it:
    parser.add_argument('-1', '--disable-postback', dest='disable_postback',
                        action="store_true", help=argparse.SUPPRESS)
    parser.add_argument('--version', action="version", version=get_version(True))

    
    run.add_parser(subparsers)
    put.add_parser(subparsers)
    get.add_parser(subparsers)
    ping.add_parser(subparsers)
    ssh_copy_id.add_parser(subparsers)
    
    return parser


