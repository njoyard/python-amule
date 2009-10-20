#!/usr/bin/env python
# This file is part of the Python aMule client library.
#
# Copyright (C) 2009  Nicolas Joyard <joyard.nicolas@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from distutils.core import setup

setup(
    name = 'amule',
    version = '0.1',
    description = 'Python aMule client library',

    classifiers = [
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.6',
        'Topic :: Communications :: File Sharing'
    ],

    author = 'Nicolas Joyard',
    author_email = 'joyard.nicolas@gmail.com',
    url = 'http://www.mnkey.ney/avhes/',

    packages = ['amule']
)
