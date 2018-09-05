#!/usr/bin/python

import os.path as op
import subprocess
import urllib.request
import sys

import portage
import gnupg
import yaml


HERE = op.dirname(op.abspath(__file__))
GPG = gnupg.GPG(gnupghome=op.join(HERE, 'gnupghome'))

def get_src_uri(cpv):
    db = portage.db['/']['porttree'].dbapi
    return db.aux_get(cpv, ('SRC_URI', ))[0]

def get_distfile_path(cpv):
    db = portage.db['/']['porttree'].dbapi
    distdir = db.settings['DISTDIR']
    distname = list(db.getFetchMap(cpv).keys())[0]
    return op.join(distdir, distname)


def get_all_cpvs(cp):
    db = portage.db['/']['porttree'].dbapi
    return db.match(cp)


def verify_package(cp, attrs):
    for gpgkey in attrs['gpg_pubkeys']:
        GPG.import_keys(open(op.join(HERE, 'keys', gpgkey), 'rb').read())
    cpvs = get_all_cpvs(cp)
    for cpv in cpvs:
        print(f"Verifying {cpv}")
        distfile = get_distfile_path(cpv)
        if not op.exists(distfile):
            print("Downloading distfile...")
            subprocess.run(['emerge', '-f', f'={cpv}'])
        src_uri = get_src_uri(cpv)
        stream = urllib.request.urlopen(f'{src_uri}.asc')
        verified = GPG.verify_file(stream, distfile)
        if verified.fingerprint in attrs['gpg_pubkeys']:
            print(f"Ok! ({verified.fingerprint})")
        else:
            print("Verification failed!")
            sys.exit(1)


def main():
    data = yaml.safe_load(open(op.join(HERE, 'info.yml')))
    for cp, attrs in data.items():
        verify_package(cp, attrs)

if __name__ == '__main__':
    main()
