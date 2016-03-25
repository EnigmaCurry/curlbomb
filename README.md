# curlbomb 

A personal HTTP server for serving one-time-use shell scripts.

You know all those docs for cool dev tools that start out by telling
you to install their software in one line, like this?

    bash <(curl -s http://example.com/install.sh)

I call that a curl bomb... I don't know if anyone else does.

This script is an HTTP server that will serve that script to a client
exactly once and then quit. Yea, you could just use "python -m http.server", 
really this is just a bit more than that.

## Install

This script can be installed from the [Arch User Repository](https://aur.archlinux.org/packages/curlbomb/) (AUR):

    pacaur -S curlbomb
	
Or from the [Python Package Index](https://pypi.python.org/pypi/curlbomb) (PyPI):

    pip install curlbomb

## Example Use

Serve a script stored in a file:

    curlbomb /path/to/script
	
This outputs a curl command to run the script on another computer:

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

You can tunnel the curlbomb server through another host with --ssh:

    echo "apt-get install emacs-nox" | curlbomb --ssh user@example.com:8080
	
The above command connects to example.com and forwards the curlbomb
HTTP port to example.com:8080. Users on example.com will be able to
fetch the resource from localhost:8080. If you want anyone in the
world to be able to fetch example.com:8080 you will need to modify
the sshd_config of the server to allow GatewayPorts:

	# Put this in your /etc/ssh/sshd_config and restart your ssh service:
    Gatewayports clientspecified

## Command Line Args

    usage: curlbomb [-h] [-k] [-n NUM_GETS] [-p PORT] [-q] [-c COMMAND] [-w]
                    [--ssh SSH_FORWARD] [--ssl CERTIFICATE]
                    [--mime-type MIME_TYPE] [--survey]
                    [FILE]
    
    curlbomb
    
    positional arguments:
      FILE                  File to serve (or don't specify for stdin)
    
    optional arguments:
      -h, --help            show this help message and exit
      -k, --disable-knock   Don't require authentication (no X-knock header)
      -n NUM_GETS           Number of times to serve resource (default:1)
      -p PORT               TCP port number to use (default:random)
      -q                    Be quiet
      -c COMMAND            The the shell command to curlbomb into (default is to
                            detect #!interpreter)
      -w                    Output wget command rather than curl
      --ssh SSH_FORWARD     Forward curlbomb through another host via SSH -
                            [user@]host[:ssh_port][:http_port]
      --ssl CERTIFICATE     Use SSL with the given certificate
      --mime-type MIME_TYPE
                            The content type to serve
      --survey              Just a survey mission, no bomb run
