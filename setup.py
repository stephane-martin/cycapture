#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages, Extension
import setuptools.command.install
import setuptools.command.build_ext
import os
import shlex
import sys
import glob
import shutil
from tempfile import mkdtemp
from distutils.log import info
import subprocess
from os.path import dirname, abspath, join, commonprefix, exists

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))


def _get_pcap_config_shared():
    cfg = {}
    dirs = ['/usr', sys.prefix] + glob.glob('/opt/libpcap*') + glob.glob('../libpcap*') + glob.glob('../wpdpack*')
    for d in dirs:
        for sd in ('include/pcap', 'include', ''):
            if exists(join(d, sd, 'pcap.h')):
                cfg['include_dirs'] = [join(d, sd)]
        for sd in ('lib', 'lib64', 'lib/x86_64-linux-gnu'):
            for lib in (('pcap', 'libpcap.a'), ('pcap', 'libpcap.so'), ('pcap', 'libpcap.dylib'), ):
                if exists(join(d, sd, lib[1])):
                    cfg['library_dirs'] = [join(d, sd)]
                    cfg['libraries'] = [lib[0]]
    return cfg

def _get_pcap_config_static(libpcap_srcdir):
    cfg = {
        'include_dirs': [join(libpcap_srcdir, 'pcap')],
        'extra_objects': [join(libpcap_srcdir, 'libpcap.a')]
    }
    return cfg

def list_subdir(subdirname):
    subdirname = join(here, subdirname)

    l = [(root, [
        join(root, f) for f in files if (not f.endswith("secrets.py")) and (
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


class MyBuildExtCommand(setuptools.command.build_ext.build_ext):

    def run(self):
        tmpdir = None
        if os.getenv("CYCAPTURE_SHARED_LIBPCAP") is not None:
            info("Building cycapture against a shared libpcap")
            pcap_config = _get_pcap_config_shared()
        else:
            tmpdir = mkdtemp()
            old_dir = os.getcwd()
            os.chdir(tmpdir)
            info("Fetching libpcap from github in %s\n" % tmpdir)
            subprocess.call(shlex.split("git clone -b libpcap-1.7 --single-branch https://github.com/the-tcpdump-group/libpcap.git"))
            info("Compiling libpcap\n")
            os.chdir("libpcap")
            subprocess.call(shlex.split("./configure --enable-shared=no"))
            subprocess.call("make")
            os.chdir(old_dir)
            info("Building cycapture as a static library")
            pcap_config = _get_pcap_config_static(libpcap_srcdir=join(tmpdir, "libpcap"))

        my_exts = [extension for extension in self.extensions if extension.name == "cycapture.libpcap"]
        if my_exts:
            my_ext = my_exts[0]
            my_ext.include_dirs = pcap_config.get('include_dirs', None)
            my_ext.library_dirs = pcap_config.get('library_dirs', None)
            my_ext.libraries = pcap_config.get('libraries', None)
            my_ext.extra_compile_args = pcap_config.get('extra_compile_args', None)
            my_ext.extra_objects = pcap_config.get('extra_objects', None)

        setuptools.command.build_ext.build_ext.run(self)
        if tmpdir:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    with open('README.rst') as readme_file:
        readme = readme_file.read()

    with open('HISTORY.rst') as history_file:
        history = history_file.read().replace('.. :changelog:', '')

    requirements = []
    remove_requirements_if_rtd = []

    if on_rtd:
        for ext in remove_requirements_if_rtd:
            requirements.remove(ext)

    test_requirements = []
    extensions = []
    if not on_rtd:
        pcap_extension = Extension(
            name="cycapture.libpcap",
            sources=["cycapture/libpcap.pyx"]
        )
        extensions.append(pcap_extension)
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
        ext_modules=extensions,
        cmdclass={'build_ext': MyBuildExtCommand}

    )
