# -*- coding: utf-8 -*-

import distutils.core
from setuptools import setup, find_packages, Extension
import os
import shlex
import sysconfig
import sys
import shutil
import subprocess
from os.path import dirname, abspath, join, exists
import distutils.sysconfig
import platform


def _info(s):
    sys.stderr.write(s + "\n")

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
here = abspath(dirname(__file__))


IS_MACOSX = platform.system().lower().strip() == "darwin"
# todo: fix windows
IS_WINDOWS = platform.system().lower().strip() == "XXXX"
disutils_sysconfig = distutils.sysconfig.get_config_vars()

if IS_MACOSX:
    # don't build useless i386 architecture
    disutils_sysconfig['LDSHARED'] = disutils_sysconfig['LDSHARED'].replace('-arch i386', '')
    disutils_sysconfig['CFLAGS'] = disutils_sysconfig['CFLAGS'].replace('-arch i386', '')
    # suppress painful warnings
    disutils_sysconfig['CFLAGS'] = disutils_sysconfig['CFLAGS'].replace('-Wstrict-prototypes', '')


class Dependency(object):
    def __init__(self):
        self.name = None
        self.static = True
        self.thisdir = abspath(dirname(__file__))
        self.external_dir = join(self.thisdir, 'includes')
        if not exists(self.external_dir):
            os.mkdir(self.external_dir)
        self._include_dirs = None
        self._library_dirs = None
        self._extra_objects = None
        self._install_dir = None
        self._extra_link_args = None

    def build(self):
        raise NotImplementedError()

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
        self.src_dir = join(self.external_dir, "libpcap")
        self.name = 'pcap'
        self.build()

    def build(self):
        old_dir = os.getcwd()
        self._install_dir = join(self.src_dir, 'build')
        os.chdir(self.src_dir)
        if exists('Makefile'):
            subprocess.call(shlex.split("make clean"))
        if not exists(
            join(self._install_dir, 'lib', 'libpcap.dylib')
        ) and not exists(
            join(self._install_dir, 'lib', 'libpcap.so')
        ):
            _info("Building libpcap as a shared library\n")
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
                join(self._install_dir, 'lib', 'libpcap.so.1'),
                join(self.thisdir, 'cycapture', 'libpcap')
            )
            os.symlink(
                join(self.thisdir, 'cycapture', 'libpcap', 'libpcap.so.1'),
                join(self.thisdir, 'cycapture', 'libpcap', 'libpcap.so')
            )
        os.chdir(old_dir)


class LibtinsDep(Dependency):
    def __init__(self, pcap_dep):
        super(LibtinsDep, self).__init__()
        self.pcap_dep = pcap_dep
        self.name = "tins"
        self.src_dir = join(self.external_dir, "libtins")
        self.build()

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
                _info('CMAKE_OSX_SYSROOT: {}'.format(os.environ["SDKROOT"]))
            # libtins.dylib will have install dir name using rpath
            cmake_options['CMAKE_MACOSX_RPATH'] = "'true'"
            _info('CMAKE_MACOSX_RPATH: true')

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
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.dylib'),
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.so'),
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.so.3.2'),
            join(self.thisdir, 'cycapture', 'libtins', 'libtins.3.2.so')
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
            try:
                shutil.copy(
                    join(self.src_dir, 'build', 'lib', 'libtins.3.2.so'),
                    join(self.thisdir, 'cycapture', 'libtins')
                )
                os.symlink(
                    join(self.thisdir, 'cycapture', 'libtins', 'libtins.3.2.so'),
                    join(self.thisdir, 'cycapture', 'libtins', 'libtins.so')
                )
            except:
                shutil.copy(
                    join(self.src_dir, 'build', 'lib', 'libtins.so.3.2'),
                    join(self.thisdir, 'cycapture', 'libtins')
                )
                os.symlink(
                    join(self.thisdir, 'cycapture', 'libtins', 'libtins.so.3.2'),
                    join(self.thisdir, 'cycapture', 'libtins', 'libtins.so')
                )

        self._include_dirs = [
            join(self.src_dir, 'include'),
            join(self.pcap_dep.install_dir(), 'include')
        ]
        self._library_dirs = [
            join(self.thisdir, 'cycapture', 'libtins'),
            join(self.thisdir, 'cycapture', 'libpcap')
        ]
        if IS_MACOSX:
            # all python extensions that are linked against libtins will have a proper rpath
            self._extra_link_args = ["-Wl,-rpath", "-Wl,@loader_path/"]

if IS_MACOSX:
    python_config_vars = sysconfig.get_config_vars()
    # use the same SDK as python executable
    if not exists(python_config_vars['UNIVERSALSDK']):
        _info("'{}' SDK does not exist. Aborting.".format(python_config_vars['UNIVERSALSDK']))
        sys.exit(-1)
    _info("Building for MacOSX SDK: {}".format(python_config_vars["MACOSX_DEPLOYMENT_TARGET"]))
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

test_requirements = ['pytest']
extensions = []

if not on_rtd:
    # utility module to make python memoryviews from char* buffers
    make_mview_extension = Extension(
        name="cycapture._make_mview",
        sources=["cycapture/_make_mview.c"]
    )
    extensions.append(make_mview_extension)

    pthread_extension = Extension(
        name="cycapture._pthreadwrap",
        sources=["cycapture/_pthreadwrap.c", "cycapture/murmur.c"]
    )
    extensions.append(pthread_extension)

    if not IS_WINDOWS:
        signal_extension = Extension(
            name="cycapture._signal",
            sources=["cycapture/_signal.c"]
        )
        extensions.append(signal_extension)

    # build libpcap and the cycapture.libpcap python extension
    pcap_extension = Extension(
        name="cycapture.libpcap._pcap",
        sources=["cycapture/libpcap/_pcap.c"]
    )
    libpcap_dep = LibpcapDep()
    # noinspection PyTypeChecker
    libpcap_dep.add_to_extension(pcap_extension)
    extensions.append(pcap_extension)

    tins_dep = LibtinsDep(libpcap_dep)

    tins_exceptions_extension = Extension(
        name="cycapture.libtins._py_exceptions",
        sources=[
            "cycapture/libtins/_py_exceptions.cpp",
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
            "cycapture/libtins/_tins.cpp",
            "cycapture/libtins/wrap.cpp",
            "cycapture/libtins/py_tcp_stream_functor.cpp",
            "cycapture/libtins/py_pdu_iterator.cpp"
        ],
        language="c++"
    )
    # noinspection PyTypeChecker
    tins_dep.add_to_extension(tins_extension)
    extensions.append(tins_extension)


def check_cmake():
    try:
        subprocess.call(['cmake', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return False
    return True

def check_flex():
    try:
        subprocess.call(['flex', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return False
    return True

def check_yacc():
    try:
        subprocess.call(['yacc', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return False
    return True


def run_setup():
    setup(
        name='cycapture',
        version='0.3',
        description='Cython bindings for libpcap and libtins',
        long_description=readme + '\n\n' + history,
        author='Stephane Martin',
        author_email='stephane.martin_github@vesperal.eu',
        url='https://github.com/stephane-martin/cycapture',
        packages=find_packages(exclude=['tests']),
        package_data={'': ['libtins.*', 'libpcap.*']},
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

        data_files=[],
        test_suite='tests',
        tests_require=test_requirements,
        ext_modules=extensions
    )

if __name__ == '__main__':
    if not check_cmake():
        _info("Please install cmake first")
        sys.exit(1)
    if not check_flex():
        _info("Please install flex first")
        sys.exit(1)
    if not check_yacc():
        _info("Please install yacc first")
        sys.exit(1)

    run_setup()
