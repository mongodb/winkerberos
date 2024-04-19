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

import sys
from setuptools import setup, Extension


if "MSC" in sys.version:
    # msvc:
    extra_link_args = [
        "crypt32.lib",
        "secur32.lib",
        "Shlwapi.lib",
        "/NXCOMPAT",
        "/DYNAMICBASE",
    ]
else:
    # mingw:
    extra_link_args = ["-lcrypt32", "-lsecur32", "-lshlwapi"]


def parse_reqs_file(fname):
    with open(fname) as fid:  # noqa:PTH123
        lines = [li.strip() for li in fid.readlines()]
    return [li for li in lines if li and not li.startswith("#")]


setup(
    install_requires=parse_reqs_file("requirements.txt"),
    ext_modules=[
        Extension(
            "winkerberos",
            extra_link_args=extra_link_args,
            sources=["src/winkerberos.c", "src/kerberos_sspi.c"],
        )
    ],
)
