# Copyright 2016 MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

if sys.version_info[:2] < (2, 7):
    raise RuntimeError("Python version >= 2.7 required.")

# http://bugs.python.org/issue15881
try:
    import multiprocessing
except ImportError:
    pass

try:
    from setuptools import setup, Extension
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, Extension

if sys.version_info[:2] < (3, 10):
    from distutils.command.build_ext import build_ext
else:
    from setuptools.command.build_ext import build_ext

try:
    import sphinx
    _HAVE_SPHINX = True
except ImportError:
    _HAVE_SPHINX = False
try:
    import sphinx.cmd.build
except ImportError:
    # older version of sphinx; should have sphinx.main and won't need this
    pass
    

# Sphinx needs to import the built extension to generate
# html docs, so build the extension inplace first.
class doc(build_ext):

    def run(self):

        if not _HAVE_SPHINX:
            raise RuntimeError(
                "You must install Sphinx to build the documentation.")

        self.inplace = True
        build_ext.run(self)

        path = os.path.join(os.path.abspath("."), "doc", "_build", "html")

        sphinx_args = ["-E", "-b", "html", "doc", path]

        # sphinx.main calls sys.exit when sphinx.build_main exists.
        # Call build_main directly so we can check status and print
        # the full path to the built docs.
        if hasattr(sphinx, 'build_main'):
            status = sphinx.build_main(sphinx_args)
        elif hasattr(sphinx, 'main'):
            status = sphinx.main(sphinx_args)
        elif hasattr(sphinx, 'cmd'):
            status = sphinx.cmd.build.main(sphinx_args)
        else:
            status = 1

        if status:
            raise RuntimeError("Documentation build failed")

        sys.stdout.write("\nDocumentation build complete. The "
                         "results can be found in %s.\n" % (path,))


with open("README.rst") as f:
    try:
        readme = f.read()
    except Exception:
        readme = ""

tests_require = ["pymongo >= 2.9"]

if 'MSC' in sys.version:
    #msvc:
    extra_link_args = ['crypt32.lib', 'secur32.lib', 'Shlwapi.lib',
           '/NXCOMPAT', '/DYNAMICBASE',
           ]
else:
    #mingw:
    extra_link_args = ['-lcrypt32',
                        '-lsecur32',
                        '-lshlwapi']

setup(
    name="winkerberos",
    version="0.9.1",
    description="High level interface to SSPI for Kerberos client auth",
    long_description=readme,
    author="Bernie Hackett",
    author_email="bernie@mongodb.com",
    url="https://github.com/mongodb-labs/winkerberos",
    keywords=["Kerberos", "SSPI", "GSSAPI"],
    install_requires=[],
    test_suite="test",
    tests_require=tests_require,
    platforms="Windows",
    license="Apache License, Version 2.0",
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: System :: Systems Administration :: Authentication/Directory"],
    ext_modules = [
        Extension(
            "winkerberos",
            extra_link_args=extra_link_args,
            sources = [
                "src/winkerberos.c",
                "src/kerberos_sspi.c"
            ],
        )
    ],
    cmdclass={"doc": doc}
)

