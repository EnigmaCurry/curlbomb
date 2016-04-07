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

from .main import *
from . import argparser, settings, server
from . import run, get, put, ping

__version__ = argparser.get_version()
