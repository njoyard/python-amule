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

from eccodes import *
from ecpacketutils import *


class ECTag:
    def __init__(self, name, type):
        self.name = name
        self.type = type
        self.subtags = []
        
    def get_subtag(self, name):
        for st in self.subtags:
            if st.name == name:
                return st
        return None

    def get_data(self, utf8_numbers):
        selfdata = self.pack()

        if len(self.subtags):
            name = (self.name << 1) | 1
            if utf8_numbers:
                data = ec_number_to_utf8(name)
            else:
                data = struct.pack("!H", name)
            data = data + struct.pack("!B", self.type)

            stdata = ""
            stlen = 0
            for st in self.subtags:
                thisdata, thislen = st.get_data(utf8_numbers)
                stdata = stdata + thisdata
                stlen = stlen + thislen

            taglen = stlen + len(selfdata)
            if utf8_numbers:
                data = data + ec_number_to_utf8(taglen)
                data = data + ec_number_to_utf8(len(self.subtags))
            else:
                data = data + struct.pack("!I", taglen)
                data = data + struct.pack("!H", len(self.subtags))

            data = data + stdata + selfdata
        else:
            name = self.name << 1
            if utf8_numbers:
                data = ec_number_to_utf8(name)
            else:
                data = struct.pack("!H", name)
            data = data + struct.pack("!B", self.type)
            taglen = len(selfdata)
            if utf8_numbers:
                data = data + ec_number_to_utf8(taglen)
            else:
                data = data + struct.pack("!I", taglen)
            data = data + selfdata

        return (data, 7 + taglen)

    def dump(self):
        s = "Name: 0x%04x (%s)\n" % (self.name, ec_tagname_str(self.name))
        s = s + "Type: 0x%02x (%s)\n" % (self.type, ec_tagtype_str(self.type))
        s = s + "Subtag count: %d\n" % len(self.subtags)
        if len(self.subtags):
            s = s + "----- SUBTAGS : -----\n"
            sts = ""
            for st in self.subtags:
                sts = sts + st.dump()
            s = s + "\n".join(["  " + a for a in sts.split("\n")]).rstrip(" ")
            s = s + "---------------------\n"
        s = s + "Value: %s\n" % repr(self.value)
        s = s + "Packed value: %s\n" % repr(self.pack())
        return s


class ECCustomTag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_CUSTOM)
        self.value = value

    def pack(self):
        return self.value


class ECUInt8Tag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_UINT8)
        self.value = value

    def pack(self):
        return struct.pack("!B", self.value)


class ECUInt16Tag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_UINT16)
        self.value = value

    def pack(self):
        return struct.pack("!H", self.value)


class ECUInt32Tag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_UINT32)
        self.value = value

    def pack(self):
        return struct.pack("!I", self.value)


class ECUInt64Tag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_UINT64)
        self.value = value

    def pack(self):
        return struct.pack("!Q", self.value)


class ECStringTag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_STRING)
        self.value = value

    def pack(self):
        return "%s\x00" % self.value


class ECDoubleTag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_DOUBLE)
        self.value = value

    def pack(self):
        return struct.pack("!d", self.value)


class ECHash16Tag(ECTag):
    def __init__(self, value, name):
        ECTag.__init__(self, name, EC_TAGTYPE_HASH16)
        self.value = value

    def pack(self):
        packed = ""
        for i in range(16):
            packed = packed + "%c" % int(self.value[2 * i:2 * i + 2], 16)
        return packed
