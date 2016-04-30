# curlbomb 

curlbomb is a personal HTTP(s) server for serving one-time-use shell scripts.

You know all those docs for the cool and hip software projects that
start out by telling you to install their software in one line, like
this?

    curl http://example.com/install.sh | bash

I call that a curl bomb... I don't know if anyone else does.

*convenient* as hell, but a security and trustability
*nightmare*. Especially since installers usually require root access,
do you trust a random file on the internet with direct access to your
machine?

But I usually try to ask myself this question: is it possible to turn
a *bad* idea into a *good* one, or at the very least a less-bad idea?
Let's take a look..

curlbomb serves a single file (read from disk or stdin) via HTTP to
the first client to request it, then it shuts down. A command is
printed out that will construct the curl bomb the client needs to run,
which includes a one-time-use passphrase (called a knock) that is
required to download the resource. This command is copy/pasted (or
typed) into another shell, on some other computer, which will download
and run the script in one line.

curlbomb has optional (but recommended) integration with OpenSSL to
secure communications. OpenSSH is supported as well, to make it easy
to curlbomb from anywhere on the internet, to anywhere else, through a
proxy server that you can forward the port through.

So does curlbomb measure up to making this a good idea? Decide for yourself:

[comment]: # (start feature table)
| Feature/Problem | Traditional curl bomb                                                                                             | Using curlbomb                                                                                                                                                       |
| -------         | ---------------------                                                                                             | -------                                                                                                                                                              |
| Conveniece      | Yup, sure is.                                                                                                     | I think so.                                                                                                                                                          |
| Trust           | Is it even SSL? Do you know/trust the URL and it's author?                                                        | Self hosted server and SSL verifies connection                                                                                                                       |
| Security        | Even if you verify the script beforehand, are you sure it hasn't changed?                                         | Self hosted script, you're in control of the contents.                                                                                                               |
| Privacy         | Anyone who knows the URL can download/run. Cannot contain private information like passwords.                     | curlbomb requires a passphrase (knock) and only serves a file one time (by default.) Put sensitive data like SSH keys and passphrases into your script as necessary. |
| Repeatability   | Is the script going to stay at the same URL forever? Can you specify any parameters or at least a version number? | It's your script, read whatever env vars you want. You can keep it checked into your own git repository and serve it from anywhere anytime.                          |
[comment]: # (end feature table)

curlbomb is well tested, but not intended for heavy automation
work. There are better alternatives to choose from (saltstack,
ansible, puppet, etc.) curlbomb can be used effectively in doing the
front work for setting up these other tools, like copying SSH keys and
installing packages.

## Install

This script can be installed from the
[Arch User Repository](https://aur.archlinux.org/packages/curlbomb/)
(AUR):

    pacaur -S curlbomb
	
Or from the
[Python Package Index](https://pypi.python.org/pypi/curlbomb) (PyPI):

    pip install curlbomb

### Dependencies

 * Python 3.5 (I haven't tested anything lower)
 * [Tornado](http://www.tornadoweb.org/)
 * [Requests](https://pypi.python.org/pypi/requests)
 * OpenSSL (optional, if using --ssl)
 * OpenSSH (optional, if using --ssh)
 * GnuPG (optional, if using encrypted SSL cert or resources)
 * [python-notify2](https://pypi.python.org/pypi/notify2) (optional, for desktop notifications when using ping subcommand)
 * curl (on the client machine, preferably version >= 7.39.0, for --pinnedpubkey support)
 
## Example Use

Serve a script stored in a file:

    curlbomb run /path/to/script
	
This outputs a curl command that you copy and paste into a shell on another
computer:

    KNOCK=nDnXXp8jkZKtbush bash <(curl -LSs http://192.0.2.100:48690)
	
Once pasted, the script is automatically downloaded and executed.

By default, the client must pass a KNOCK variable that is passed in
the HTTP headers. This is for two reasons:

 * It adds a factor of authentication. Requests without the knock are
   denied.
 * It helps to prevent mistakes, as the knock parameter is randomly
   generated each time curlbomb is run and can only be used once. (See
   `-n 1`)

(Astute readers will notice that the KNOCK variable is being fed to
the script that is being downloaded, not into the curl command. That's
because it's really a curlbomb within a curlbomb. The first curl
command downloads a script that includes a second curl command that
*does* require the KNOCK parameter. This nesting allows us to keep the
client command as short as possible and hide some extra
boilerplate. See `--unwrapped`.)

If you want just the curl, without the bomb, ie. you just want to grab
the script without redirecting it to bash, use `--survey`. This is
useful for testing the retrieval of scripts without running them.

You can pipe scripts directly into curlbomb:

    echo "pacman --noconfirm -S openssh && systemctl start sshd" | curlbomb
	
Whenever you pipe data to curlbomb you can omit the `run` subcommand,
it's assumed that you want to run a script from stdin.
	
This works in shell scripts too:

    cat <<EOF | curlbomb
    #!/bin/bash
    echo "I'm a script output from another script on another computer"
    EOF

Or type it interactively:

    $ curlbomb run -
    pkg instll sqlite3
    echo "bad idea, I don't have spollcheck when I typ in the terminal"

(The single dash says to read from stdin, even when nothing is being
piped. Ctrl-D ends the interactive input.)

The shebang line (#!) is interpreted and automatically changes the
interpreter the client runs, the following example runs the script
with python instead of the default bash:

    cat <<EOF | curlbomb
    #!/usr/bin/env python3
    import this
    print("Hello, from Python!")
    EOF

curlbomb can also transfer files and directories with `put` and `get`
subcommands:

    # Recursively copy a directory 
    # (to whatever directory the client is run from):
    curlbomb put ~/.ssh

    # Recursively copy a remote directory to the server
    # (to whatever directory the server is run from)
    curlbomb get /var/log 

    # Recursively copy a directory
    #  - Specifies the explicit remote destination directory.
    #  - Environment vars in single quotes are evaluated on the remote end.
    #  - Excludes some files you may want to keep private.
    curlbomb put ~/.ssh '$HOME' --exclude='*rsa'

The `put` and `get` subcommands are just convenience wrappers for
running tar on both ends of the curlbomb pipe. You *could* achieve the
same thing more generically:

    # Copy a local directory to a client, the hard way:
    tar cjh -C $HOME .ssh | curlbomb run -c "tar xjv -f"
    
    # Copy a remote directory to the server, the hard way:
    echo "tar cjh -C /var log" | curlbomb -l --client-quiet | tar xjv

The first example has a `run -c` parameter that tells the client that
we want to interpret the data as being a tar archive rather than a
script. The second example has a `-l` parameter that will output the
data received to stdout, in this case piped directly into tar.

### SSH tunnel

By default, curlbomb constructs URLs with the IP address of the local
machine. This usually means that clients on another network will be
unable to retrieve anything from curlbomb, unless you have a port
opened up through your firewall (and appropriate use of the `--domain`
and `--port` arguments.) As an alternative, curlbomb can be tunneled
through SSH to another host that has the proper port open. For
instance:

    echo "apt-get install salt-minion" | curlbomb --ssh user@example.com:8080
	
The above command connects to example.com over SSH (port 22 by
default) and forwards the curlbomb server port to
example.com:8080. The URL that curlbomb prints out will now use the
domain name of the ssh server, instead of the local IP address. The
SSH tunnel is left open for as long as the curlbomb server remains
running. Any user directly on the example.com host will be able to
fetch the resource from localhost:8080. However, by default, SSH does
not open this up to the rest of the world. If you want any client to
be able to connect to example.com:8080 you will need to modify the
sshd_config of the server to allow GatewayPorts:

    # Put this in your /etc/ssh/sshd_config and restart your ssh service:
    GatewayPorts clientspecified

### TLS / SSL security

For extra security, you can enable TLS with `--ssl`:

    echo "PASSWORD=hunter2 run_my_server" | curlbomb --ssl /path/to/cert.pem

The example above is passing a bit of secure information; a
password. Even without TLS, curlbomb secures access with a knock
parameter. For many use-cases, this is sufficient to secure it, as
curlbombs are short lived and can only be retrieved one time (`-n
1`). However, the connection itself might be spied on (or even
modified!) through traffic analysis at your ISP or any other router
your connection flows through. Using TLS makes sure this doesn't
happen. 

Note that when the `--ssl` parameter is combined with the `--ssh`
parameter, the SSL certificate should be generated for the host
running the SSH server rather than the one running curlbomb. To
prevent having to store the SSL certificate in plain text on your
local machine, the file may be optionally PGP encrypted and curlbomb
will decrypt it only when necessary.

You can also specify `--ssl` by itself, without the path. In this
case, a new self-signed certificate will be generated and used for
this session only.

`--pin` can be used to extract the SSL certificate fingerprint and
directly provide it to the client curl command (requires curl >=7.39). 
This avoids having to trust the client's CA root certificate
store, and trusts your certificate explicitly. When generating a
self-signed certificate with `--ssl`, the `--pin` option is turned on
automatically. Pinning adds some extra security benefits, but makes
the client command you have to paste/type much longer than it usually
is, for example:

    $ echo "whoami" | curlbomb --ssl
    WARNING:curlbomb.server:No SSL certificate provided, creating a new self-signed certificate for this session
    Paste this command on the client:
	
      KNOCK=bbxfOV1ToDVhJjAl bash <(curl -LSs -k --pinnedpubkey 'sha256//RSkhZc2Qw/j8AxHMLUzipRpegEK9I0BlX7J1I5bcg0Y=' https://192.0.2.100:39817)
	  
`--pin` is a different kind of trust model then using a certificate
signed by a CA. When you use `--pin` you are completely bypassing the
root CA certificate store of the client machine and instructing it to
trust your certificate explicitly. This mitigates many
man-in-the-middle type attacks that can happen with TLS, but you still
need to take care that the client command is not modified or
eavesdropped before being pasted into the client.

### Aliases

By now the curlbomb command might be getting quite long. Once you've
encrypted and stored your SSL certificate, and setup your SSH server,
create an alias for ease of use, for example:

    alias cb=curlbomb --ssl ~/.curlbomb/curlbomb.pem.gpg --ssh user@example.com:22:8080

There's a few more examples in [EXAMPLES.md](EXAMPLES.md)

## Command Line Args

    curlbomb [-h] [-n N] [-p PORT] [-d host[:port]] [-w] [-l] [-q] [-v]
             [-1] [--ssh SSH_FORWARD] [--ssl [CERTIFICATE]] [--pin]
             [--survey] [--unwrapped] [--client-logging] [--client-quiet]
             [--mime-type MIME_TYPE] [--disable-knock] [--knock KNOCK]
             [--version]
             {run,put,get,ping,ssh-copy-id} ...
				   
curlbomb has a few subcommands:

 * `run` - run a shell script
 * `put` - copy local files/directories to remote system
 * `get` - copy remote files/directories to local system
 * `ping` - wait for a client to finish a task, with optional
   notification command
 * `ssh-copy-id` - copy SSH public keys to the remote authorized_keys
   file
 
If no subcommand is specified, and there is data being piped to stdin,
then the `run` subcommand is used implicitly.

### The following arguments apply to all subcommands:

`-n N, --num-gets N` The maximum number of times the script may be
fetched by clients, defaulting to 1. Increasing this may be useful in
certain circumstances, but please note that the same knock parameter
is used for all requests so this is inherently less secure than the
default. Setting this to 0 will allow the resource to be downloaded an
unlimited number of times.

`-p PORT` The local TCP port number to use.

`-d host[:port], --domain host[:port]` Specify the domain name and
port that is displayed in the URL of the client command. This does not
change where the resource is actually located, use --port or --ssh for
that. This is useful if you are setting up your own port forwards and
need to show an external URL.

`-w, --wget` Print wget syntax rather than curl syntax. Useful in the
case where the client doesn't have curl installed. Not compatible with
`--log--posts` or the `put` and `get` subcommands. :(

`-l, --log-posts` Log the client stdout to the server stdout. This is
off by default, but is turned on automatically when you pipe curlbomb
stdout to another process (unless you use -q.)

`-q, --quiet` Be more quiet. Don't print the client curlbomb command.

`-v, --verbose` Be more verbose. Turns off `--quiet`, enables
`--log-posts`, and enables INFO level logging within curlbomb.

`--ssh SSH_FORWARD` Forwards the curlbomb server to a remote port of
another computer through SSH. This is useful to serve curlbombs to
clients on another network without opening up any ports to the machine
running curlbomb. The syntax for SSH_FORWARD is
[user@]host[:ssh_port][:http_port]. The SSH server must have the
GatewayPorts setting turned on to allow remote clients to connect to
this port. See sshd_config(5).

`--ssl [CERTIFICATE]` Run the HTTP server with TLS
encryption. Optionally provide the full path to your SSL certificate,
which may be PGP encrypted. The file should contain the entire
certificate chain, including the CA certificate, if any. If no SSL
certificate path is provided, a temporary self-signed certificate will
be generated for the current curlbomb session and `--pin` will be
turned on implicitly.

`--pin` (requires curl>=7.39.0) Pin the SSL certificate fingerprint
into the client curl command. This is used to bypass the root CA store
of the client machine, and to tell it exactly what the server's SSL
certificate looks like. This is useful for mitigating
man-in-the-middle attacks, as well as when using self-signed
certificates. This makes the client command quite a bit longer than
usual.

`--survey` Only print the curl (or wget) command. Don't redirect to a
shell command. Useful for testing script retrieval without running
them.

`--unwrapped` output the full curlbomb command, including all the
boilerplate that curlbomb normally wraps inside of a nested curlbomb.

This parameter is useful when you want to source variables into your
current shell:

    echo "export PATH=/asdf/bin:$PATH" | curlbomb -c source --unwrapped --disable-postback

Without the --unwrapped option, the client command will not run the
source command directly, but instead a bash script with a source
inside it. This won't work for sourcing environment variables in your
shell, so use --unwrapped when you want to use
source. --disable-postback prevents the command from being piped back
to the server (as source doesn't have any output, and strangely fails
to do it's job when you do pipe it somewhere else.)

`-1, --disable-postback` Disables sending client output to the
server. This is necessary for interactive scripts. Note that
--log-posts will have no effect with this enabled.

`--client-logging` Logs all client output locally on the client to a
file called curlbomb.log

`--client-quiet` Quiets the output on the client

`--mime-type MIME_TYPE` The mime-type header to send, by default
"text/plain"

`--disable-knock` Don't require a X-knock HTTP header from the
client. Normally, curlbombs are one-time-use and meant to be
copy-pasted from terminal to terminal. If you're embedding into a
script, you may not know the knock parameter ahead of time and so this
disables that. This is inherently less secure than the default.

`--version` Print the curlbomb version

### Run subcommand

    curlbomb run [-c COMMAND] [--hash SHA256] [--signature FILE_OR_URL [GPG_ID ...]] [SCRIPT]

Runs a shell script on the remote client.

`-c COMMAND` Set the name of the command that the curlbomb is run with
on the client. By default, this is autodected from the first line of
the script, called the shebang (#!). If none can be detected, and one
is not provided by this setting, the fallback of "bash" is used. Note
that curlbomb will still wrap your script inside of bash, even with `-c`
specified, so the client command will still show it as running in
bash. The command you specified is put into the wrapped script. See
`--unwrapped` to change this behaviour.

`--hash SHA256` Specify the expected SHA-256 hash of the script and
the server will verify that it actually has that hash before the
server starts. This is useful if you are pipeing a script from
someplace outside of your control, like from the network. This
prevents the server from serving a script other than the version you
were expecting.

`--signature FILE_OR_URL [GPG_ID ...]` Specify the file or URL
containing the GPG signature for the script. Optionally specify a list
of GPG key identifiers that are allowed to sign the script. If no
GPG_ID is specified, any valid signature from your keyring is
accepted. The script will be checked for a valid signature before the
server starts.

`SCRIPT` The script or other resource to serve via curlbomb. You can
also leave this blank (or specify '-') and the resource will be read
from stdin.

Note that the run subcommand is implied if you are pipeing data to
curlbomb. For instance, this command is assumed that the run command
is desired even if not explicitly used:

    echo "./run_server.sh" | curlbomb

Which is equivalent to:

    echo "./run_server.sh" | curlbomb run -

### Put subcommand

    curlbomb put [--exclude=PATTERN] SOURCE [DEST]

Copies file(s) from the local SOURCE path to the remote DEST path. If
a directory is specified, all child paths will be copied recursively.

If DEST path is unspecified, files/directories will be copied to the
working directory of wherever the client was run.

Exclude patterns can be specified like tar(1)

### Get subcommand

    curlbomb get [--exclude=PATTERN] SOURCE [DEST]

Copies file(s) from the remote SOURCE path to the local DEST path. If
a directory is specified, all child paths will be copied recursively.

If DEST path is unspecified, files/directories will be copied to the
working directory of wherever curlbomb was run.

Exclude patterns can be specified like tar(1)

### Ping subcommand

    curlbomb ping [-m MESSAGE] [-r RETURN_CODE] [--return-success]
	              [-c COMMAND] [-n]

Serves an empty body resource for the purposes of pinging the server
when the client has finished some task.

`-m` sets the message the client will respond with.

`-r` sets the return code the client will respond with. This is used
as the main curlbomb return code on the server as well. If `-n` > 1,
the last non-zero return code received is used instead, defaulting to
0.

`--return-success` Always return 0, regardless of the return code(s)
received.

`-c COMMAND` Run this command for each ping received. You can use the
following placeholders to format ping data: {return_code} and
{message}. {message} is replaced surrounded by quotes, so no need to
do that again in your command.

### ssh-copy-id subcommand

    curlbomb ssh-copy-id IDENTITY
	
Copies the given OpenSSH identity file (eg. ~/.ssh/id_rsa.pub) into
the remote ~/.ssh/authorized_keys file.

Of course OpenSSH comes with it's own ssh-copy-id program, but I've
never really understood the usefulness of it. The idea of using SSH
keys is to not use crappy passwords, right? But the OpenSSH version of
ssh-copy-id requires password authentication (at least temporarily
during the setup process.) So you either have to edit your
sshd_config, turn on `PasswordAuthentication`, and restart the
service, or you resign yourself to run an insecure sshd all the
time. `curlbomb ssh-copy-id` is easier and works in more situations.

Another difference in this version is that you must explicity specify
the identity file, whereas the OpenSSH version does some automatic
determination of which key to install. Especially if you maintain
several ssh identities, being explicit seems the more sane thing to do
than try to save some keystrokes and inevitably install the wrong key
on the server.
