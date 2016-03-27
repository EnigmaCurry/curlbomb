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

The client must pass a X-knock HTTP header by default. This is for two
reasons:

 * It adds a factor of authentication. Requests without the knock are
   denied.
 * It prevents mistakes as the knock parameter is randomly generated each
   time curlbomb is run. 

You can disable the knock requirement with the -k option. 

If you want the curl, without the bomb, ie. you just want to grab the
script without redirecting it to bash, use --survey. This is useful
for testing the retrieval of scripts without running them. 

You can also pipe scripts directly into curlbomb:

    echo "pacman --noconfirm -S openssh && systemctl start sshd" | curlbomb
	
Or from shell scripts:

    cat <<EOF | curlbomb
    #!/bin/bash
    echo "I'm a script output from another script on another computer"
	EOF

The shebang line (#!) is interpreted and automatically changes the curlbomb command:

    cat <<EOF | curlbomb
	#!/usr/bin/env python3
	import this
	print("Hello, from Python!")
	EOF
	
Which outputs the following curlbomb, tailored for Python:

    /usr/bin/env python3 <(curl http://10.13.37.133:55298 -H "X-knock: 3b4bc96e29754238a30c286d1c8173c7")

You can use -c to specify your own command if the shebang line is
missing, or misidentified. "bash" is always used as a fallback.

If your client doesn't have curl installed, you can switch to wget
with -w:

    $ echo "apt-get install curl" | curlbomb -w
	Client command:

      bash <(wget -q -O - http://10.13.37.133:57670 --header="X-knock: 5e5568bf44624e70a7490783acee150d")

By default, curlbomb serves from the local IP address. This usually
means that clients on another network will be unable to retrieve
anything from curlbomb, unless you have a port opened up through your
firewall. As an alternative, curlbomb can be tunneled through SSH to
another host that has the proper port open. For instance:

    echo "apt-get install emacs-nox" | curlbomb --ssh user@example.com:8080
	
The above command connects to example.com over SSH (port 22 by
default) and forwards the local curlbomb HTTP port to
example.com:8080. This SSH tunnel is left open for as long as curlbomb
remains running. Any user on example.com will be able to fetch the
resource from localhost:8080. If you want anyone in the world to be
able to fetch example.com:8080 you will need to modify the sshd_config
of the server to allow GatewayPorts:

	# Put this in your /etc/ssh/sshd_config and restart your ssh service:
    Gatewayports clientspecified

For extra security, you can enable SSL with --ssl:

    echo "export PASSWORD=hunter2" | curlbomb -c source --ssl /path/to/cert.pem

In the above example we are passing a bit of secure information, a
password. curlbomb normally prevents access with a knock paramter, but
the knock itself might be spied on through traffic analysis. Using SSL
makes sure this doesn't happen. To prevent having to store the SSL
certificate in plain text on your local machine, the file may be
optionally PGP encrypted in an ascii-armored file. This will be
automatically decrypted if you are running a gpg-agent.

## Command Line Args

    usage: curlbomb [-h] [-k] [-n NUM_GETS] [-p PORT] [-q] [-c COMMAND] [-w]
                    [--ssh SSH_FORWARD] [--ssl CERTIFICATE]
                    [--mime-type MIME_TYPE] [--survey]
                    [FILE]
    
`-k` Don't require a X-knock HTTP header from the client. Normally
curlbombs are one-time-use and meant to be copy-pasted from terminal
to terminal. If you're embedding into a script, you may not know the
knock parameter ahead of time and so this disables that. This is
inherently less secure than the default.

`-n NUM_GETS` The maximum number of times the script may be fetched by clients,
defaults to 1. Increasing this may be useful in certain circumstances,
but please note that the same knock parameter is used for all requests
so this is inherently less secure than the default.

`-p PORT` The local TCP port number to use

`-q` Be quiet. Don't print the curlbomb.

`-c COMMAND` Force the curlbomb shell command. By default, this is autodected
from the first line of the script, called the shebang (#!). If none
can be detected, and one is not provided, the fallback of "bash" is
used.

`--survey` Only print the curl (or wget) command. Don't redirect to a
shell command. Useful for testing out script retrieval without running
them. 

`-w` Print wget syntax rather than curl syntax. Useful in the case
where the client doesn't have curl installed.

`--ssh SSH_FORWARD` Forwards the curlbomb server to a remote port of another
computer through SSH. This is useful to serve curlbombs to clients on
another network without opening up any ports to the machine running
curlbomb. The syntax for SSH_FORWARD is [user@]host[:ssh_port][:http_port].

`--ssl CERTIFICATE` Full server to client http encryption using
SSL. Give the full path to your SSL certificate, optionally PGP
(ascii-armored) encrypted.

`--mime-type MIME_TYPE` The mime-type header to send, by default "text/plain"

`FILE` The script or other resource to serve via curlbomb. You can
also not specify this and the resource will be read from stdin.
