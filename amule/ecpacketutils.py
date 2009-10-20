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

import struct
import eccodes

def ec_code_str(prefix, value):
    """Search for EC codes by value

    Return the first symbol name in eccodes, which starts with prefix and
    evaluates to value, or None if none found.

    """

    for s in dir(eccodes):
        if s.startswith(prefix) and eval("eccodes.%s" % s) == value:
            return s
    return None

def ec_opcode_str(value):
    """Get the first EC opcode name that evaluates to value"""
    return ec_code_str("EC_OP_", value)

def ec_tagname_str(value):
    """Get the first EC tag name that evaluates to value"""
    return ec_code_str("EC_TAG_", value)

def ec_tagtype_str(value):
    """Get the first EC tag type that evaluates to value"""
    return ec_code_str("EC_TAGTYPE_", value)

def ec_number_to_utf8(number):
    """UTF8-encode a number into a string"""
    return unichr(number).encode('utf-8')

def ec_read_utf8(buf):
    """UTF8-decode a number from a file-like buffer"""
    string = buf.read(1)
    bytes = struct.unpack("!B", string)[0]
    if (bytes & 0xF8) == 0xF0:
        string = string + buf.read(3)
    elif (bytes & 0xF0) == 0xE0:
        string = string + buf.read(2)
    elif (bytes & 0xE0) == 0xC0:
        string = string + buf.read(1)
    return ord(string.decode('utf-8'))
