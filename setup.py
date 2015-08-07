#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages, Extension
import os
import shlex
import platform
import sys
import shutil
from distutils.log import info
import subprocess
import urllib
import tarfile
from os.path import dirname, abspath, join, commonprefix, exists

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))


class Dependency(object):
    def __init__(self):
        self.name = ""
        self.language = "c"
        self.static = True
        self.thisdir = abspath(dirname(__file__))
        self.external_dir = join(self.thisdir, 'external')
        if not exists(self.external_dir):
            os.mkdir(self.external_dir)
        self._include_dirs = None
        self._library_dirs = None
        self._extra_objects = None
        self._install_dir = None


    def download(self):
        pass

    def build(self):
        pass

    def extra_compile_args(self):
        return []

    def install_dir(self):
        return self._install_dir

    def include_dirs(self):
        if self._include_dirs:
            return self._include_dirs
        return []

    def extra_objects(self):
        if self._extra_objects:
            return self._extra_objects
        return []

    def library_dirs(self):
        if self._library_dirs:
            return self._library_dirs
        return []


    def add_to_extension(self, ext):
        ext.include_dirs.extend(self.include_dirs())
        ext.library_dirs.extend(self.library_dirs())
        if self.name:
            ext.libraries.append(self.name)
        ext.language = self.language
        ext.extra_objects.extend(self.extra_objects())




class LibpcapDep(Dependency):
    def __init__(self):
        super(LibpcapDep, self).__init__()
        self.name = "pcap"
        self.src_dir = join(self.external_dir, "libpcap")

        if os.getenv("USE_SHARED_PCAP"):
            self.static = False
            # find an existing shared libpcap
            include_dirs, library_dirs = self.find_shared_libpcap(os.getenv("LIBPCAP_PREFIX"))
            if include_dirs is None or library_dirs is None:
                raise RuntimeError("an existing shared libpcap library was not found")
            info("Using shared libpcap: %s, %s" % (include_dirs, library_dirs))
            self._install_dir = dirname(library_dirs[0])            # hum...
            self._include_dirs = include_dirs
            self._library_dirs = library_dirs

        elif os.getenv("COMPILE_SHARED_PCAP"):
            # compile a shared libpcap, then install the .so directly in cython sources
            self.static = False
            self.download()
            self.build()

        else:
            # compile a static libpcap
            self.download()
            self.build()


    def download(self):
        if not exists(self.src_dir):
            info("Fetching libpcap from github in %s\n" % self.external_dir)
            old_dir = os.getcwd()
            os.chdir(self.external_dir)
            subprocess.call(shlex.split("git clone -b libpcap-1.7 --single-branch https://github.com/the-tcpdump-group/libpcap.git"))
            os.chdir(old_dir)

    def build(self):
        old_dir = os.getcwd()
        self._install_dir = join(self.src_dir, 'build')
        os.chdir(self.src_dir)
        if exists('Makefile'):
            subprocess.call(shlex.split("make clean"))
        if self.static:
            if not exists(join(self._install_dir, 'lib', 'libpcap.a')):
                info("Building libpcap as a static library\n")
                subprocess.call(shlex.split("./configure --enable-shared=no --prefix='%s'" % self._install_dir))
                subprocess.call("make")
                subprocess.call(shlex.split("make install"))
                self._include_dirs = [join(self._install_dir, 'include')]
                self._extra_objects = [join(self._install_dir, 'lib', 'libpcap.a')]
        else:
            if not exists(join(self._install_dir, 'lib', 'libpcap.dylib')):
                info("Building libpcap as a shared library\n")
                subprocess.call(shlex.split("./configure --prefix='%s'" % self._install_dir))
                subprocess.call("make")
                subprocess.call(shlex.split("make install"))
                self._include_dirs = [join(self._install_dir, 'include')]
                self._library_dirs = [join(self._install_dir, 'lib')]
                try:
                    shutil.copy(join(self._install_dir, 'lib', 'libpcap.dylib'), join(self.thisdir, 'cycapture', 'libpcap'))
                except:
                    shutil.copy(join(self._install_dir, 'lib', 'libpcap.so'), join(self.thisdir, 'cycapture', 'libpcap'))
        os.chdir(old_dir)

    @classmethod
    def find_shared_libpcap(cls, prefix=None):
        dirs = ['/usr', '/usr/local', '/opt', sys.prefix]
        if prefix is not None:
            dirs.insert(0, prefix)

        def _find_include():
            for d in dirs:
                for sd in ('include/pcap', 'include', ''):
                    if exists(join(d, sd, 'pcap.h')):
                        return [join(d, sd)]

        def _find_library():
            for d in dirs:
                for sd in ('lib', 'lib64', 'lib/x86_64-linux-gnu'):
                    for lib in (('pcap', 'libpcap.a'), ('pcap', 'libpcap.so'), ('pcap', 'libpcap.dylib'), ):
                        if exists(join(d, sd, lib[1])):
                            return [join(d, sd)]

        return _find_include(), _find_library()


class LibtinsDep(Dependency):
    def __init__(self, pcap_dep):
        super(LibtinsDep, self).__init__()
        self.pcap_dep = pcap_dep
        self.name = ""              # we dont want setup.py to add a -ltins to the link step
        self.language = "c++"
        self.src_dir = join(self.external_dir, "libtins")
        self.download()
        self.build()

    def download(self):
        if not exists(self.src_dir):
            info("Fetching libtins from github in %s\n" % self.external_dir)
            old_dir = os.getcwd()
            os.chdir(self.external_dir)
            urllib.urlretrieve("https://github.com/mfontanini/libtins/archive/v3.2.tar.gz", "v3.2.tar.gz")
            t = tarfile.open("v3.2.tar.gz", mode='r:gz')
            try:
                t.extractall()
            finally:
                t.close()
            os.remove("v3.2.tar.gz")
            shutil.move("libtins-3.2", "libtins")
            os.chdir(old_dir)

    def build(self):
        old_dir = os.getcwd()
        os.chdir(self.src_dir)
        if not exists('build'):
            os.mkdir('build')
        os.chdir('build')
        subprocess.call(shlex.split(
            "cmake ../ -DCMAKE_CXX_FLAGS='-fPIC' -DLIBTINS_BUILD_SHARED=0 -DPCAP_ROOT_DIR='%s'" % self.pcap_dep.install_dir()
        ))
        subprocess.call('make')
        os.chdir(old_dir)
        self._include_dirs = [join(self.src_dir, 'include')]
        self._extra_objects = [join(self.src_dir, 'build', 'lib', 'libtins.a')]

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
        # utility module to make python memoryviews from char* buffers
        make_mview_extension = Extension(
            name="cycapture.make_mview",
            sources=["cycapture/make_mview.pyx"]
        )
        extensions.append(make_mview_extension)

        # build libpcap and the cycapture.libpcap python extension
        pcap_extension = Extension(
            name="cycapture.libpcap._pcap",
            sources=["cycapture/libpcap/_pcap.pyx"]
        )
        pcap_dep = LibpcapDep()
        # noinspection PyTypeChecker
        pcap_dep.add_to_extension(pcap_extension)
        extensions.append(pcap_extension)

        # build libtins and cycapture.libtins python extension
        tins_extension = Extension(
            name="cycapture.libtins._tins",
            sources=["cycapture/libtins/_tins.pyx", "cycapture/libtins/wrap.cpp", "cycapture/libtins/custom_exception_handler.cpp"]
        )
        tins_dep = LibtinsDep(pcap_dep)
        # noinspection PyTypeChecker
        tins_dep.add_to_extension(tins_extension)
        extensions.append(tins_extension)
    data_files = []

    # see http://lists.gnu.org/archive/html/libtool-patches/2014-09/msg00002.html`
    # http://stackoverflow.com/questions/26563079/mac-osx-getting-segmentation-faults-on-every-c-program-even-hello-world-af
    if platform.mac_ver()[0].startswith('10.10'):
        os.environ["MACOSX_DEPLOYMENT_TARGET"] = "10.9"
    setup(
        name='cycapture',
        version='0.2',
        description='Cython bindings for libpcap and libtins',
        long_description=readme + '\n\n' + history,
        author='Stephane Martin',
        author_email='stephane.martin_github@vesperal.eu',
        url='https://github.com/stephane-martin/cycapture',
        packages=find_packages(exclude=['tests']),
        setup_requires=[
            'setuptools_git', 'setuptools', 'twine', 'wheel', 'cython'
        ],
        include_package_data=True,
        exclude_package_data={'': ['*.c', '*.cpp', '*.h']},
        install_requires=requirements,
        license="LGPLv3+",
        zip_safe=False,
        keywords='libpcap cython python libtins',
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
