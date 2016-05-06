curlbomb cookbook
=================

There's several examples in the [README](README.md) for how to use
curlbomb, but here's a few more.

I put the following into my ~/.bashrc to setup an alias for the most
common options I use with curlbomb:

    # Run curlbomb via a public SSH proxy with TLS:
    alias cb="curlbomb --ssh ryan@example.com:8080 --ssl ~/.curlbomb/curlbomb.pem.gpg"

Verified curlbomb proxy
-----------------------

Most often I use curlbomb to serve my own scripts, but I sometimes use
it with external scripts too. In this mode, curlbomb is acting as a
proxy for the upstream script and verifies it's integrity in the
process.

Here's an example to download the official
[sandstorm](https://sandstorm.io/) installer script, verify it's GPG
signature, make sure the signature was from support@sandstorm.io, then
serve:

    curl https://install.sandstorm.io | curlbomb --pipe run --signature https://install.sandstorm.io/install.sh.sig support@sandstorm.io

(The `--pipe` parameter is necessary due to the way that the sandstorm
install script is written to check for interactive terminals. If your
use case does not use an interactive script you can omit `--pipe`)
	
This requires that first of all you have the sandstorm GPG keys loaded
into your GPG keyring as [documented in their install guide](https://docs.sandstorm.io/en/latest/install/#option-3-pgp-verified-install) :

    gpg --import <(curl https://raw.githubusercontent.com/sandstorm-io/sandstorm/master/keys/release-keyring.gpg)

You will, of course, want to **carefully verify** that the imported signatures are correct.

You can also verify the script by it's SHA256 hash:

    curl https://install.sandstorm.io | curlbomb run --hash eaaf6d2077e1a093662edb46c028c9a68b70790bee256d90d8ada7da2250c309
	
This will verify that the script has the exact SHA256 hash
specified. If the script ever changes, curlbomb will refuse to serve
the file until you update the hash.


Remotely invoke curlbomb
------------------------

You can create a curlbomb and invoke it on a remote server in one line:

    echo "whoami" | curlbomb | ssh ryan@example.com
	
curlbomb prints out the client command to stdout when pipeing curlbomb
output. This is passed to ssh and run verbatim.

Old examples
------------

I used to put these in my bashrc, before I wrote the put and get subcommands:

    # curlbomb to push a local file or directory to a client:
    # Always put the argument in quotes to allow pushing 
    # multiple paths at the same time, as well as using globs.
    cb_put() {
        if [ -z "$1" ]; then
            echo "Must specify the path to tar"
            return
        fi
        tar cjh $1 | cb -c "tar xjvf"
    }

    # curlbomb to retrieve a remote file or directory from the client:
    # Always put the argument in quotes to allow retrieving
    # multiple paths at the same time, as well as using globs. 
    # To reference remote variable names, make sure to use single quotes.
    cb_get() {
        if [ -z "$1" ]; then
            echo "Must specify the remote path to get"
            return
        fi
        echo "tar cjh $1" | cb -l | tar xjv
    }

