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
import subprocess
import sys

try:
    from setuptools import setup, Extension
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, Extension

from distutils.command.build_ext import build_ext

# Sphinx needs to import the built extension to generate
# html docs, so build the extension inplace first.
class doc(build_ext):

    def run(self):
        self.inplace = True
        build_ext.run(self)

        path = os.path.join("doc", "_build", "html")

        status = subprocess.call(["sphinx-build",
                                  "-E",
                                  "-b",
                                  "html",
                                  "doc",
                                  path])

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
if sys.version_info[:2] == (2, 6):
    tests_require.append("unittest2 >= 0.5.1")
    test_suite = "unittest2.collector"
else:
    test_suite = "test"

setup(
    name="winkerberos",
    version="0.1.0.dev0",
    description="High level interface to SSPI for Kerberos client auth",
    long_description=readme,
    author="Bernie Hackett",
    author_email="bernie@mongodb.com",
    url="https://github.com/mongodb-labs/winkerberos",
    keywords=["Kerberos", "SSPI", "GSSAPI"],
    install_requires=[],
    test_suite=test_suite,
    tests_require=tests_require,
    platforms="Windows",
    license="Apache License, Version 2.0",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: System :: Systems Administration :: Authentication/Directory"],
    ext_modules = [
        Extension(
            "winkerberos",
            extra_link_args=['secur32.lib', '/NXCOMPAT', '/DYNAMICBASE'],
            sources = [
                "src/winkerberos.c",
                "src/kerberos_sspi.c",
                "src/base64.c"
            ],
        )
    ],
    cmdclass={"doc": doc}
)

