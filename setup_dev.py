#!/usr/bin/env python
# -*- coding: utf-8 -*-

import distutils.core
from setuptools import setup, find_packages, Extension
import os
import shlex
import sysconfig
import sys
import shutil
import subprocess
import urllib
import tarfile
from os.path import dirname, abspath, join, commonprefix, exists
import distutils.sysconfig
import platform


def info(s):
    sys.stderr.write(s + "\n")


on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))


IS_MACOSX = platform.system().lower().strip() == "darwin"
disutils_sysconfig = distutils.sysconfig.get_config_vars()
if IS_MACOSX:
    # don't build useless i386 architecture
    disutils_sysconfig['LDSHARED'] = disutils_sysconfig['LDSHARED'].replace('-arch i386', '')
    disutils_sysconfig['CFLAGS'] = disutils_sysconfig['CFLAGS'].replace('-arch i386', '')
    # suppress painful warnings
    disutils_sysconfig['CFLAGS'] = disutils_sysconfig['CFLAGS'].replace('-Wstrict-prototypes', '')


class Dependency(object):
    def __init__(self):
        self.name = ""
        self.static = True
        self.thisdir = abspath(dirname(__file__))
        self.external_dir = join(self.thisdir, 'external')
        if not exists(self.external_dir):
            os.mkdir(self.external_dir)
        self._include_dirs = None
        self._library_dirs = None
        self._extra_objects = None
        self._install_dir = None
        self._extra_link_args = None

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

    def extra_link_args(self):
        if self._extra_link_args:
            return self._extra_link_args
        return []

    def add_to_extension(self, ext):
        ext.include_dirs.extend(self.include_dirs())
        ext.library_dirs.extend(self.library_dirs())
        if self.name:
            ext.libraries.append(self.name)
        ext.extra_objects.extend(self.extra_objects())
        ext.extra_link_args.extend(self.extra_link_args())




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
            self.name = ''
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
            else:
                info("Skipping libpcap build (already have libpcap.a)")
            self._include_dirs = [join(self._install_dir, 'include')]
            self._extra_objects = [join(self._install_dir, 'lib', 'libpcap.a')]
        else:
            if not exists(
                    join(self._install_dir, 'lib', 'libpcap.dylib')
            ) and not exists(
                join(self._install_dir, 'lib', 'libpcap.so')
            ):
                info("Building libpcap as a shared library\n")
                subprocess.call(shlex.split("./configure --prefix='%s'" % self._install_dir))
                subprocess.call("make")
                subprocess.call(shlex.split("make install"))
            self._include_dirs = [join(self._install_dir, 'include')]
            self._library_dirs = [join(self._install_dir, 'lib')]
            try:
                shutil.copy(
                    join(self._install_dir, 'lib', 'libpcap.dylib'),
                    join(self.thisdir, 'cycapture', 'libpcap')
                )
            except:
                shutil.copy(
                    join(self._install_dir, 'lib', 'libpcap.so'),
                    join(self.thisdir, 'cycapture', 'libpcap')
                )
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
        self.name = "tins"
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

        cmake_options = {
            'CMAKE_CXX_FLAGS': "'-fPIC'",
            'LIBTINS_BUILD_SHARED': "'1'",
            'PCAP_ROOT_DIR': "'{}'".format(self.pcap_dep.install_dir())
        }
        if IS_MACOSX:
            if bool(os.environ["SDKROOT"]):
                # path to the macosx SDK that was used to compile python
                cmake_options['CMAKE_OSX_SYSROOT'] = "'{}'".format(os.environ["SDKROOT"])
                info('CMAKE_OSX_SYSROOT: {}'.format(os.environ["SDKROOT"]))
            # libtins.dylib will have install dir name using rpath
            cmake_options['CMAKE_MACOSX_RPATH'] = "'true'"
            info('CMAKE_MACOSX_RPATH: true')

        cmake_options = ' '.join(['-D{}={}'.format(opt_name, opt_value) for opt_name, opt_value in cmake_options.items()])

        subprocess.call(shlex.split(
            "cmake ../ " + cmake_options
        ))
        subprocess.call('make')
        os.chdir(old_dir)

        files_to_remove = [
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.3.2.dylib'),
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.dylib'),
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.3.2.dylib'),
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.dylib')
        ]

        for fname in files_to_remove:
            try:
                os.remove(fname)
            except OSError:
                pass

        try:
            shutil.copy(
                join(self.src_dir, 'build', 'lib', 'libtins.3.2.dylib'),
                join(self.thisdir, 'cycapture', 'libtins')
            )
            os.symlink(
                join(self.thisdir, 'cycapture', 'libtins', 'libtins.3.2.dylib'),
                join(self.thisdir, 'cycapture', 'libtins', 'libtins.dylib')
            )
        except:
            shutil.copy(
                join(self.src_dir, 'build', 'lib', 'libtins.3.2.so'),
                join(self.thisdir, 'cycapture', 'libtins')
            )
            os.symlink(
                join(self.thisdir, 'cycapture', 'libtins', 'libtins.3.2.so'),
                join(self.thisdir, 'cycapture', 'libtins', 'libtins.so')
            )
        self._include_dirs = [join(self.src_dir, 'include')]
        self._library_dirs = [join(self.thisdir, 'cycapture', 'libtins')]
        if IS_MACOSX:
            # all python extensions that are linked against libtins will have a proper rpath
            self._extra_link_args = ["-Wl,-rpath", "-Wl,@loader_path/"]


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
    if IS_MACOSX:
        python_config_vars = sysconfig.get_config_vars()
        # use the same SDK as python executable
        if not exists(python_config_vars['UNIVERSALSDK']):
            info("'{}' SDK does not exist. Aborting.\n".format(python_config_vars['UNIVERSALSDK']))
            sys.exit(-1)
        info("Building for MacOSX SDK: {}".format(python_config_vars["MACOSX_DEPLOYMENT_TARGET"]))
        os.environ["MACOSX_DEPLOYMENT_TARGET"] = python_config_vars["MACOSX_DEPLOYMENT_TARGET"]
        os.environ["SDKROOT"] = python_config_vars["UNIVERSALSDK"]

    with open('README.rst') as readme_file:
        readme = readme_file.read()

    with open('HISTORY.rst') as history_file:
        history = history_file.read().replace('.. :changelog:', '')

    requirements = ['enum34']
    remove_requirements_if_rtd = []

    if on_rtd:
        for ext in remove_requirements_if_rtd:
            requirements.remove(ext)

    test_requirements = ['nose']
    extensions = []
    if not on_rtd:
        # utility module to make python memoryviews from char* buffers
        make_mview_extension = Extension(
            name="cycapture._make_mview",
            sources=["cycapture/_make_mview.pyx"]
        )
        extensions.append(make_mview_extension)

        pthread_extension = Extension(
            name="cycapture._pthreadwrap",
            sources=["cycapture/_pthreadwrap.pyx", "cycapture/murmur.c"]
        )
        extensions.append(pthread_extension)

        signal_extension = Extension(
            name="cycapture._signal",
            sources=["cycapture/_signal.pyx"]
        )
        extensions.append(signal_extension)

        # build libpcap and the cycapture.libpcap python extension
        pcap_extension = Extension(
            name="cycapture.libpcap._pcap",
            sources=["cycapture/libpcap/_pcap.pyx"]
        )
        libpcap_dep = LibpcapDep()
        # noinspection PyTypeChecker
        libpcap_dep.add_to_extension(pcap_extension)
        extensions.append(pcap_extension)

        tins_dep = LibtinsDep(libpcap_dep)

        tins_exceptions_extension = Extension(
            name="cycapture.libtins._py_exceptions",
            sources=[
                "cycapture/libtins/_py_exceptions.pyx",
                "cycapture/libtins/custom_exception_handler.cpp"
            ],
            language="c++"
        )

        # noinspection PyTypeChecker
        tins_dep.add_to_extension(tins_exceptions_extension)
        extensions.append(tins_exceptions_extension)

        # build libtins and cycapture.libtins python extension
        tins_extension = Extension(
            name="cycapture.libtins._tins",
            sources=[
                "cycapture/libtins/_tins.pyx",
                "cycapture/libtins/wrap.cpp",
                "cycapture/libtins/py_tcp_stream_functor.cpp",
                "cycapture/libtins/py_pdu_iterator.cpp"
            ],
            language="c++"
        )
        # noinspection PyTypeChecker
        tins_dep.add_to_extension(tins_extension)
        extensions.append(tins_extension)

    data_files = []

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
            'setuptools_git', 'setuptools', 'twine', 'wheel', 'nose'
        ],
        include_package_data=True,
        exclude_package_data={},
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

