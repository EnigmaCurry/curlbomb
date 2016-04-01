# curlbomb 

curlbomb is an HTTP(s) server for serving one-time-use shell scripts.

You know all those docs for cool dev tools that start out by telling
you to install their software in one line, like this?

    bash <(curl -s http://example.com/install.sh)

I call that a curl bomb... I don't know if anyone else does.

curlbomb reads a file, or from stdin, and then serves it one time to
the first client to retrieve it. A command is printed out that will
construct the curl bomb the client needs to run, which includes a
one-time-use passphrase (called a knock) required to download the
resource. This command is copied and run in another shell, on some
other computer, to download and run the script in one line.

curlbomb has optional integration with OpenSSH to make it easy to
curlbomb from anywhere on the internet, to anywhere else, through a
proxy server that you can forward the port through.

## Install

This script can be installed from the [Arch User Repository](https://aur.archlinux.org/packages/curlbomb/) (AUR):

    pacaur -S curlbomb
	
Or from the [Python Package Index](https://pypi.python.org/pypi/curlbomb) (PyPI):

    pip install curlbomb

## Example Use

Serve a script stored in a file:

    curlbomb /path/to/script
	
This outputs a curl command to run the script on another computer:

    KNOCK='nDnXXp8jkZKtbush' bash <(curl -LSs http://192.0.2.100:48690)

By default, the client must pass a KNOCK variable that is passed in
the HTTP headers. This is for two reasons:

 * It adds a factor of authentication. Requests without the knock are
   denied.
 * It helps to prevent mistakes, as the knock parameter is randomly
   generated each time curlbomb is run and can only be used once. (-n 1)

(Astute readers will notice that the KNOCK variable is being fed to
the script that is being downloaded, not into the curl command. That's
because it's really a curlbomb within a curlbomb. The first curl
command downloads a script that includes a second curl command that
*does* require the KNOCK parameter. This nesting allows us to keep the
client command as short as possible and hide some extra
boilerplate. See --unwrapped.)

If you want the curl, without the bomb, ie. you just want to grab the
script without redirecting it to bash, use --survey. This is useful
for testing the retrieval of scripts without running them (or as an
ad-hoc way to copy files between two computers that don't have ssh
setup.)

You can also pipe scripts directly into curlbomb:

    echo "pacman --noconfirm -S openssh && systemctl start sshd" | curlbomb
	
Or from shell scripts:

    cat <<EOF | curlbomb
    #!/bin/bash
    echo "I'm a script output from another script on another computer"
	EOF

Or type it interactively:

    $ curlbomb -
	pkg instll sqlite3
	echo "bad idea, I don't have spollcheck when I typ in the terminal"

The shebang line (#!) is interpreted and automatically changes the
interpreter the client runs:

    cat <<EOF | curlbomb
	#!/usr/bin/env python3
	import this
	print("Hello, from Python!")
	EOF

If your client doesn't have curl installed, you can switch to wget
with -w:

    echo "apt-get install curl" | curlbomb -w

By default, curlbomb constructs URLs with the IP address of the local
machine. This usually means that clients on another network will be
unable to retrieve anything from curlbomb, unless you have a port
opened up through your firewall. As an alternative, curlbomb can be
tunneled through SSH to another host that has the proper port
open. For instance:

    echo "apt-get install emacs-nox" | curlbomb --ssh user@example.com:8080
	
The above command connects to example.com over SSH (port 22 by
default) and forwards the local curlbomb HTTP port to
example.com:8080. The URL that curlbomb prints out uses the domain
name of the ssh server instead of the local IP address. The SSH tunnel
is left open for as long as curlbomb remains running. Any user on
example.com will be able to fetch the resource from
localhost:8080. However, by default, SSH does not open this up to the
rest of the world. If you want any client to be able to connect to
example.com:8080 you will need to modify the sshd_config of the server
to allow GatewayPorts:

	# Put this in your /etc/ssh/sshd_config and restart your ssh service:
    GatewayPorts clientspecified

For extra security, you can enable TLS with --ssl:

    echo "PASSWORD=hunter2 run_my_server" | curlbomb --ssl /path/to/cert.pem

The example above is passing a bit of secure information; a
password. Even without TLS, curlbomb secures access with a knock
parameter. For many use-cases, this is sufficient to secure it, as
curlbombs are short lived and can only be retrieved one time (-n
1). However, the connection itself might be spied on through traffic
analysis at your ISP or any other router your connection flows
through. Using TLS makes sure this doesn't happen. 

Note that when combined with the --ssh parameter, the SSL certificate
should be generated for the host running the server rather than the
one running curlbomb. To prevent having to store the SSL certificate
in plain text on your local machine, the file may be optionally PGP
encrypted (ascii-armored) and curlbomb will decrypt it only when
necessary.

## Command Line Args

    usage: curlbomb.py [-h] [-k] [-n N] [-p PORT] [-c CMD] [-w] [-l] [-q] [-v]
                       [--ssh SSH_FORWARD] [--ssl CERTIFICATE] [--survey]
                       [--unwrapped] [--disable-postback] [--client-logging]
                       [--mime-type MIME_TYPE] [--version]
                       [FILE]
    
`-k, --disable-knock` Don't require a X-knock HTTP header from the
client. Normally curlbombs are one-time-use and meant to be
copy-pasted from terminal to terminal. If you're embedding into a
script, you may not know the knock parameter ahead of time and so this
disables that. This is inherently less secure than the default.

`-n N, --num-gets N` The maximum number of times the script may be
fetched by clients, defaulting to 1. Increasing this may be useful in
certain circumstances, but please note that the same knock parameter
is used for all requests so this is inherently less secure than the
default. Setting this to 0 will allow the resource to be downloaded an
unlimited number of times.

`-p PORT` The local TCP port number to use.

`-c COMMAND` Set the name of the command that the curlbomb is run with
on the client. By default, this is autodected from the first line of
the script, called the shebang (#!). If none can be detected, and one
is not provided by this setting, the fallback of "bash" is used. Note
that curlbomb will still wrap your script inside of bash, even with -c
specified, so the client command will still show it as running in
bash. The command you specified is put into the wrapped script. See
--unwrapped to change this behaviour.

`-w, --wget` Print wget syntax rather than curl syntax. Useful in the
case where the client doesn't have curl installed.

`-l, --log-posts` Log the client output from the curlbomb server. 

`-q, --quiet` Be more quiet. Don't print the client curlbomb command.

`-v, --verbose` Be more verbose. Turns off --quiet, enables
--log-posts, and enables INFO level logging within curlbomb.

`--ssh SSH_FORWARD` Forwards the curlbomb server to a remote port of
another computer through SSH. This is useful to serve curlbombs to
clients on another network without opening up any ports to the machine
running curlbomb. The syntax for SSH_FORWARD is
[user@]host[:ssh_port][:http_port]. The SSH server must have the
GatewayPorts (see: man sshd_config) setting turned on to allow remote
clients to connect to this port.

`--ssl CERTIFICATE` Run the HTTP server with TLS encryption. Give the
full path to your SSL certificate, optionally PGP (ascii-armored)
encrypted. The file should contain the entire certificate chain,
including the CA certificate, if any.

`--survey` Only print the curl (or wget) command. Don't redirect to a
shell command. Useful for testing out script retrieval without running
them.

`--unwrapped` output the full curlbomb command, including all the
boilerplate that curlbomb normally wraps inside of a nested curlbomb.

This parameter is useful when you want to source variables into your
current shell:

    echo "export PATH=/asdf/bin:$PATH" | curlbomb -c source --unwrapped --disable-postback

Without the --unwrapped option, the client command will not run the
'source' command directly, but instead a bash script with a 'source'
inside it. This won't work for sourcing environment variables in your
shell, so use --unwrapped when you want to use
source. --disable-postback prevents the command from being piped back
to the server (as source doesn't have any output, and strangely fails
to do it's job when you do pipe it somewhere else.)

`--disable-postback` Disables sending client output to the
server. Note that --log-posts will have no effect with this enabled.

`--client-logging` Logs all client output locally on the client to a
file called curlbomb.log

`--mime-type MIME_TYPE` The mime-type header to send, by default
"text/plain"

`--version` Print the curlbomb version

`FILE` The script or other resource to serve via curlbomb. You can
also leave this blank (or specify '-') and the resource will be read
from stdin.
