# curlbomb 

A personal HTTP server for serving one-time-use bash scripts (think installers)

You know all those docs for cool dev tools that start out by telling
you to install their software in one line, like this?

    bash <(curl -s http://example.com/install.sh)

I call that a curl bomb... I don't know if anyone else does.

This script is an HTTP server that will serve that script to a client
exactly once and then quit. Yea, you could just use "python -m http.server", 
really this is just a bit more than that.

## Usage

    curlbomb.py [-h] [-k] [-n NUM_GETS] [--ssl CERTIFICATE] [--mime-type MIME_TYPE] FILE
    
    positional arguments:
      FILE                  File to serve
    
    optional arguments:
      -h, --help            show this help message and exit
      -k, --disable-knock   Don't require authentication (no X-knock header)
                            (default: False)
      -n NUM_GETS           Number of times to serve resource (default: 1)
      --ssl CERTIFICATE     Use SSL with the given certificate (default: None)
      --mime-type MIME_TYPE
                            The content type to serve the file as (default:
                            text/plain)
