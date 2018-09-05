# upstreamsig

Verify distfiles of Gentoo package with upstream GPG keys.

We trust Gentoo developers to verify, when applicable, distfiles with GPG
signatures from upstream. However, there is no easy way to do so. This project
aims to correct that.

The goal is to document upstream GPG keys and signature locations.

Each package has a list of accepted GPG key fingerprints, keys are in the
`keys` subfolder.

Each commit in this repo is supposed to be signed by a gentoo developer, so
your source of trust is the Gentoo developer keyring.

## Dependencies

* Python 3.6+
* Portage
* `dev-python/pyyaml`
* `dev-python/python-gnupg`
* A user in the `portage` group (or running as `sudo`)

## Usage

After having installed dependencies, run:

    $ ./verify.py

It will go through all documented packages, download distfiles and then verify
them against the documented signature files.

