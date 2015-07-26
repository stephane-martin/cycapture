#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages, Extension
import os
import sys
import glob
import platform
from os.path import dirname, abspath, join, commonprefix, expanduser

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))

if not on_rtd:
    from Cython.Build import cythonize


def _get_pcap_config_shared():
    cfg = {}
    dirs = ['/usr', sys.prefix] + glob.glob('/opt/libpcap*') + glob.glob('../libpcap*') + glob.glob('../wpdpack*')
    for d in dirs:
        for sd in ('include/pcap', 'include', ''):
            if os.path.exists(os.path.join(d, sd, 'pcap.h')):
                cfg['include_dirs'] = [os.path.join(d, sd)]
        for sd in ('lib', 'lib64', 'lib/x86_64-linux-gnu'):
            for lib in (('pcap', 'libpcap.a'), ('pcap', 'libpcap.so'), ('pcap', 'libpcap.dylib'), ):
                if os.path.exists(os.path.join(d, sd, lib[1])):
                    cfg['library_dirs'] = [os.path.join(d, sd)]
                    cfg['libraries'] = [lib[0]]
    return cfg

def _get_pcap_config_static():
    pass



def list_subdir(subdirname):
    subdirname = join(here, subdirname)

    l = [(root, [
        os.path.join(root, f) for f in files if (not f.endswith("secrets.py")) and (
            f.endswith('.conf') or
            f.endswith('.config') or
            f.endswith('_plugins') or
            f.endswith('.sample') or
            f.endswith('.sql') or
            f.endswith('.patterns') or
            f.endswith('.txt'))
    ]) for root, dirs, files in os.walk(subdirname)]
    prefix_len = len(commonprefix(list(d[0] for d in l)))
    l = [(root[prefix_len + 1:], list_of_files) for root, list_of_files in l if list_of_files]
    return l


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read().replace('.. :changelog:', '')

requirements = []

not_requirements_on_rtd = []

if on_rtd:
    for ext in not_requirements_on_rtd:
        requirements.remove(ext)

test_requirements = []


if __name__ == "__main__":
    if not on_rtd:
        pcap_config = _get_pcap_config_shared()
        extensions = []
        pcap_extension = Extension(
            name="cycapture.libpcap",
            sources=["cycapture/libpcap.pyx"],
            include_dirs=pcap_config.get('include_dirs', ''),
            library_dirs=pcap_config.get('library_dirs', ''),
            libraries=pcap_config.get('libraries', ''),
            extra_compile_args=pcap_config.get('extra_compile_args', ''),
            extra_objects=pcap_config.get('extra_objects', '')
        )
        extensions.append(pcap_extension)
    else:
        extensions = None
    data_files = []
    setup(
        name='cycapture',
        version='0.1',
        description='Cython bindings for libpcap',
        long_description=readme + '\n\n' + history,
        author='Stephane Martin',
        author_email='stephane.martin_github@vesperal.eu',
        url='https://github.com/stephane-martin/cycapture',
        packages=find_packages(exclude=['tests']),
        setup_requires=[
            'setuptools_git', 'setuptools', 'twine', 'wheel', 'cython'
        ],
        include_package_data=True,
        install_requires=requirements,
        license="LGPLv3+",
        zip_safe=False,
        keywords='libpcap cython python',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
            'Natural Language :: English',
            'Programming Language :: Python :: 2.7',
            'Environment :: Console',
            'Operating System :: POSIX :: Linux'
        ],
        entry_points={
            'console_scripts': []
        },

        data_files=data_files,
        test_suite='tests',
        tests_require=test_requirements,
        ext_modules=extensions
    )
