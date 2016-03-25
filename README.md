# curlbomb 

A personal HTTP server for serving one-time-use bash scripts (think installers)

You know all those docs for cool dev tools that start out by telling
you to install their software in one line, like this?

    bash <(curl -s http://example.com/install.sh)

I call that a curl bomb... I don't know if anyone else does.

This script is an HTTP server that will serve that script to a client
exactly once and then quit. Yea, you could just use "python -m http.server", 
really this is just a bit more than that.

## Example Use

Serve a script stored in a file:

    curlbomb /path/to/script
	
This outputs a curl command to run the script on aanother computer:

    Client command:

      bash <(curl http://10.13.37.133:47601 -H "X-knock: c19fed96a78844b982053448e44060f9")

You can also get the curl without the bomb by specifying --survey.
This outputs just the inner curl command, which is useful for testing.

You can pipe scripts to stdin:

    echo "pacman --noconfirm -S openssh && systemctl start sshd" | curlbomb
	
Or from shell scripts:

    cat <<EOF | curlbomb
    #!/bin/bash
    echo "I'm a script output from another script on another computer"
	EOF

The shebang line is interpreted and automatically changes the curlbomb command:

    cat <<EOF | curlbomb
	#!/usr/bin/env python3
	import this
	print("Hello, from Python!")
	EOF
	
Which outputs the following curlbomb, tailored for Python:

    /usr/bin/env python3 <(curl http://10.13.37.133:55298 -H "X-knock: 3b4bc96e29754238a30c286d1c8173c7")

You can switch to wget with -w:

    $ echo "apt-get install curl" | curlbomb -w
	Client command:

      bash <(wget -q -O - http://10.13.37.133:57670 --header="X-knock: 5e5568bf44624e70a7490783acee150d")

## Command Line Args

    usage: curlbomb [-h] [-k] [-n NUM_GETS] [-p PORT] [-q] [-c COMMAND]
                    [--ssl CERTIFICATE] [--mime-type MIME_TYPE] [--survey]
                    [FILE]
    
    curlbomb
    
    positional arguments:
      FILE                  File to serve (default: <_io.TextIOWrapper
                            name='<stdin>' mode='r' encoding='UTF-8'>)
    
    optional arguments:
      -h, --help            show this help message and exit
      -k, --disable-knock   Don't require authentication (no X-knock header)
                            (default: False)
      -n NUM_GETS           Number of times to serve resource (default: 1)
      -p PORT               TCP port number to use (default: random)
      -q                    Be quiet (default: False)
      -c COMMAND            The the shell command to curlbomb into (default: AUTO)
      --ssl CERTIFICATE     Use SSL with the given certificate (default: None)
      --mime-type MIME_TYPE
                            The content type to serve the file as (default:
                            text/plain)
      --survey              Just a survey mission, no bomb run (default: False)
