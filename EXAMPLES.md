curlbomb cookbook
-----------------

There's several examples in the [README](README.md) for how to use curlbomb, but here's a few more.

I put the following stuff in my ~/.bashrc to setup aliases for common commands:

    # Run curlbomb via a public SSH proxy with TLS:
    alias cb="curlbomb --ssh ryan@example.com:8080 --ssl ~/.curlbomb/curlbomb.pem.gpg"

	# curlbomb function to create a tarball of a local directory 
	# and extract it on the client:
	curlbomb_tar() {
        if [ -z "$1" ]; then
            echo "Must specify the path to tar"
            return
        fi
        tar cjh $1 | cb -c "tar xjv -f"
    }

