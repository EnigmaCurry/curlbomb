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

def add_inheritible_args(parser, subcommand=None):
    """Add the root curlbomb arguments to a (sub)parser

    specify subcommand=None for the root parser, substitute the
    subcommand name for subparsers.

    This allows core arguments to be specified either before or after
    the subparser name:

        curlbomb --ssh example.com:8080 run

    is equivalent to:
    
        curlbomb run --ssh example.com:8080
    
    Argparser default values, when combined with subparsers, is very
    tricky. You must follow these rules:

      * Arguments defined in this function MUST NOT have a default
        value (other than None). Values defined as store_true, must
        specify their default as None. Defaults are specified in
        settings:get_settings(). Without this rule, default values of
        the subparser will always take precedence over the parent
        parser value, *even if it's specified on the command line!*
        
        eg: curlbomb -n 5 run script.sh (If the run subcommand
        specifies n defaults to 1, this command is actually mistakenly
        run as -n 1)

      * Arguments must have a dest name prefixed with their subcommand
        name followed by a '_' when inherited into a subparser
        (eg. "run_ssh" for the run version of --ssh). This further
        decouples the subparser version from the root parser, and
        enables you to tell which one was used (by inspecting each
        value and seeing if it's None)

        This requires you to always check BOTH the main value as well
        as the sub_value (args.ssh and args.run_ssh). This logic is
        encapsulated in get_arg_value()

    """
    def dest(name):
        return ("" if not subcommand else subcommand + "_") + name
    server = parser.add_argument_group("These args modify the server")
    server.add_argument('-n', '--num-gets', metavar="N",
                        help="Number of times to serve resource (default:1)",
                        type=int, dest=dest("num_gets"))
    server.add_argument('-p', '--port',  metavar="PORT", help="TCP port number to use "
                        "(default:random available)",
                        dest=dest("port"))
    server.add_argument('--ssh', metavar="SSH_FORWARD", dest=dest("ssh"),
                        help="Forward curlbomb through another host via SSH - "
                        "[user@]host[:ssh_port][:http_port]")
    server.add_argument('--ssl', metavar="CERTIFICATE",
                        help="Use SSL with the given certificate file "
                        "(optionally PGP encrypted.) CERTIFICATE may be specified as a "
                        "single - to generate a new self-signed certificate and to turn "
                        "on --pin", default=None, dest=dest("ssl"))
    server.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt resource with GPG before serving. Will use a randomly generated "
                        "symmetric passphrase unless --encrypt-to or --passphrase is specified.",
                        dest=dest("encrypt"), default=None)
    server.add_argument("--encrypt-to", action="append", metavar="GPG_ID", help="Encrypt with the "
                        "public key specified instead of a passphrase. Can be specified multiple times.",
                        dest=dest("encrypt_to"))
    server.add_argument("--passphrase", action="store_true",
                        help="Ask for a symmetric passphrase to encrypt with instead of a random one.",
                        dest=dest("passphrase"), default=None)
    server.add_argument('--mime-type', metavar="MIME/TYPE", help="The content type to serve",
                        dest=dest("mime_type"))
    server.add_argument('--disable-knock', action="store_true",
                        help="Don't require authentication (no X-knock header)",
                        dest=dest("disable_knock"), default=None)
    server.add_argument('--knock', metavar="KNOCK", help="Use a specific knock rather than random",
                        dest=dest("knock"))

    client = parser.add_argument_group("These args modify the client command")
    client.add_argument('-d','--domain', metavar="host[:port]",
                        help="Provide the domain and port to display "
                        "in the constructed URL. (example.com:8080)",
                        dest=dest("domain"))
    client.add_argument('-w', '--wget', 
                        help="Output wget command rather than curl",
                        action="store_true", dest=dest("wget"), default=None)
    client.add_argument('--survey', help="Just a survey mission, no bomb run "
                        "(just get the script, don't run it)", action="store_true",
                        dest=dest("survey"), default=None)
    client.add_argument('--unwrapped',
                        help="Get the unwrapped version of the curlbomb "
                        "(1 less server request, but longer command)", action="store_true",
                        dest=dest("unwrapped"), default=None)
    client.add_argument('--pin', help="Pin the SSL certificate hash into the client "
                        "command to force curl to use our certificate"
                        " (requires --ssl)", action="store_true", dest=dest("pin"),
                        default=None)
    
    cli = parser.add_argument_group("These args modify CLI interaction")
    cli.add_argument('-l','--log-posts', dest=dest("log_post_backs"), action="store_true",
                        help="Log client stdout to server stdout", default=None)
    cli.add_argument('-q', '--quiet', action="store_true",
                        help="Be more quiet. Don't print the curlbomb command",
                        dest=dest("quiet"), default=None)
    cli.add_argument('-v', '--verbose', action="store_true",
                        help="Be more verbose. Enables --log-posts and print INFO logging",
                        dest=dest("verbose"), default=None)
    cli.add_argument('--log', metavar="LOG_FILE", dest=dest("log_file"),
                        help="log messages to LOG_FILE instead of stdout")
    cli.add_argument('--client-logging', dest=dest("client_logging"),
                        help="Enable client execution log (curlbomb.log on client)",
                        action="store_true", default=None)
    cli.add_argument('--client-quiet', dest=dest("client_quiet"),
                        help="Quiet the output on the client",
                        action="store_true", default=None)
    cli.add_argument('--pipe', help="Pipe to shell command rather than doing process substitution. "
                        "This is necessary for most interactive scripts.",
                        action="store_true", dest=dest("pipe"), default=None)
    cli.add_argument('--debug', action="store_true", default=None,
                        # Be really verbose, turn on debug logging
                        help=argparse.SUPPRESS, dest=dest("debug"))
    cli.add_argument('--version', action="version", version=get_version(True))
    
def argparser(formatter_class=argparse.HelpFormatter):
    parser = argparse.ArgumentParser(
        description='curlbomb is an HTTP server for serving one-time-use shell scripts',
        formatter_class=formatter_class)
    parser.set_defaults(subcommand=None)
    subparsers = parser.add_subparsers()
    
    add_inheritible_args(parser)

    # Old disabled method for disabling postback logging:
    # Now this just outputs an error if the user uses it:
    parser.add_argument('-1', '--disable-postback',
                        action="store_true", help=argparse.SUPPRESS, default=None)
    
    run.add_parser(subparsers)
    put.add_parser(subparsers)
    get.add_parser(subparsers)
    ping.add_parser(subparsers)
    ssh_copy_id.add_parser(subparsers)
    
    return parser


