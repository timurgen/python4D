from distutils.command.build import build
from setuptools import setup, find_packages
from setuptools.command.install import install
from distutils.ccompiler import new_compiler
import os

def get_ext_modules():
    import p4d
    return [p4d.ffi.verifier.get_extension()]

class CFFIBuild(build):
    #----------------------------------------------------------------------
    def finalize_options(self):
        """"""
        self.distribution.ext_modules = get_ext_modules()
        build.finalize_options(self)

class CFFIInstall(install):
    #----------------------------------------------------------------------
    def finalize_options(self):
        """"""
        self.distribution.ext_modules = get_ext_modules()
        install.finalize_options(self)

setup(
    zip_safe=False,
    name="python4D",
    version="1.7",
    install_requires=["cffi","python-dateutil" ],
    setup_requires=['cffi', 'python-dateutil' ],
    packages=find_packages(),
    # need to include these files to be able to build our shared library
    package_data={'python4D': ['py_fourd.h'],},
    cmdclass={
        "build": CFFIBuild,
        "install": CFFIInstall,
    },
    author="Marciano Barros",
    author_email="marcianobarros20@hotmail.com",
    url="https://github.com/marcianobarros20/p4d",
    description="Python DBI module for the 4D database",
    long_description="This module provides a Python Database API v2.0 compliant driver for the 4D (4th Dimension, http://www.4d.com ) database. Based off of C library code provided by 4th Dimension and implemented using CFFI",
    license='BSD',
    classifiers=['Development Status :: 5 - Production/Stable',
                 'License :: OSI Approved :: BSD License',
                 'Intended Audience :: Developers',
                 'Topic :: Database',
                 'Programming Language :: Python :: 3',
                 'Programming Language :: Python :: 2'],
    keywords='datababase drivers DBI 4d'
)
