curlbomb cookbook
-----------------

There's several examples in the [README](README.md) for how to use curlbomb, but here's a few more.

I put the following stuff in my ~/.bashrc to setup aliases for common commands:

    # Run curlbomb via a public SSH proxy with TLS:
    alias cb="curlbomb --ssh ryan@example.com:8080 --ssl ~/.curlbomb/curlbomb.pem.gpg"

    # curlbomb to push a local file or directory to a client:
    # Always put the argument in quotes. This allows pushing 
    # multiple paths at the same time, as well as using globs.
    cb_put() {
        if [ -z "$1" ]; then
        echo "Must specify the path to tar"
        return
        fi
        tar cjh $1 | cb -c "tar xjvf"
    }

    # curlbomb to retrieve a remote file or directory from the client:
    # Always put the argument in quotes. This allows retrieving
    # multiple paths at the same time, as well as using globs. 
    # To reference remote variable names, make sure to use single quotes.
    cb_get() {
        if [ -z "$1" ]; then
        echo "Must specify the remote path to get"
        return
        fi
        echo "tar cjh $1" | cb -l | tar xjv
    }

