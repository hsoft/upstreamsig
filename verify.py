#!/usr/bin/python

import os.path as op
import subprocess
import urllib.request
import sys
import tempfile
import hashlib
from functools import partial

import portage
import gnupg
import yaml


HERE = op.dirname(op.abspath(__file__))
GPG = gnupg.GPG(gnupghome=op.join(HERE, 'gnupghome'))


def get_distfile_path(name):
    db = portage.db['/']['porttree'].dbapi
    distdir = db.settings['DISTDIR']
    return op.join(distdir, name)


def get_all_cpvs(cp):
    db = portage.db['/']['porttree'].dbapi
    return db.match(cp)


def download_distfile_if_needed(distfile, cpv):
    if not op.exists(distfile):
        print("Downloading distfile...")
        subprocess.run(['emerge', '-f', f'={cpv}'])


def verify_file(path, key_url, accepted_keys):
    stream = urllib.request.urlopen(key_url)
    verified = GPG.verify_file(stream, path)
    if verified.fingerprint in accepted_keys:
        print(f"Ok! ({verified.fingerprint})")
    else:
        if verified.fingerprint:
            print(f"Good sig but disallowed fingerprint: {verified.fingerprint}")
        else:
            print("Verification failed!")
        sys.exit(1)

def verify_cpv_asc(cpv, attrs, ext='asc'):
    db = portage.db['/']['porttree'].dbapi
    src_uri = db.aux_get(cpv, ('SRC_URI', ))[0]
    distname = list(db.getFetchMap(cpv).keys())[0]
    distpath = get_distfile_path(distname)
    download_distfile_if_needed(distpath, cpv)
    verify_file(distpath, f'{src_uri}.{ext}', attrs['gpg_pubkeys'])


def verify_cpv_firefox(cpv, attrs):
    db = portage.db['/']['porttree'].dbapi
    fetchmap = db.getFetchMap(cpv)
    distname, src_uri = [(k, v[0]) for k, v in fetchmap.items() if k.endswith('source.tar.xz')][0]
    distpath = get_distfile_path(distname)
    download_distfile_if_needed(distpath, cpv)
    root_url = '/'.join(src_uri.split('/')[:-2])
    sha512sums = urllib.request.urlopen(root_url + '/SHA512SUMS').read()
    sha512sums_sig_url = root_url + '/SHA512SUMS.asc'
    with tempfile.NamedTemporaryFile() as fp:
        fp.write(sha512sums)
        fp.flush()
        verify_file(fp.name, sha512sums_sig_url, attrs['gpg_pubkeys'])
    sha512 = hashlib.sha512(open(distpath, 'rb').read()).hexdigest()
    if f'{sha512}  source/{distname}'.encode() in sha512sums:
        print(f"Ok! ({sha512})")
    else:
        print(f"Wrong SHA512 sum! ({sha512})")
        sys.exit(1)



CHECKFUNCS = {
    'asc': verify_cpv_asc,
    'sig': partial(verify_cpv_asc, ext='sig'),
    'firefox': verify_cpv_firefox,
}

def verify_package(cp, attrs):
    for gpgkey in attrs['gpg_pubkeys']:
        GPG.import_keys(open(op.join(HERE, 'keys', gpgkey), 'rb').read())
    cpvs = get_all_cpvs(cp)
    for cpv in cpvs:
        print(f"Verifying {cpv}")
        checkfunc = CHECKFUNCS[attrs.get('pattern', 'asc')]
        checkfunc(cpv, attrs)



def main():
    data = yaml.safe_load(open(op.join(HERE, 'info.yml')))
    for cp, attrs in data.items():
        verify_package(cp, attrs)

if __name__ == '__main__':
    main()
