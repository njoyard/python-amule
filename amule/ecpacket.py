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
from cStringIO import StringIO
import zlib

from eccodes import *
from ectag import *
from ecpacketutils import *


class ECUnknownTagtypeError(Exception): pass
class ECRemainingBytesError(Exception): pass


class ECPacket:
    def __init__(self, **kwargs):
        self.tags = []
        self.flags = EC_FLAG_BLANK
        self.accept_flags = EC_FLAG_BLANK
        self.opcode = kwargs.get('opcode', EC_OP_NOOP)

        if kwargs.has_key('rawdata'):
            self._parse_raw_packet(kwargs['rawdata'])
        elif kwargs.has_key('buffer'):
            self._read_raw_packet(kwargs['buffer'])

    def set_flag(self, flag):
        self.flags = self.flags | flag

    def get_flag(self, flag):
        return self.flags & flag

    def set_accept_flag(self, flag):
        self.accept_flags = self.accept_flags | flag

    def get_accept_flag(self, flag):
        return self.accept_flags & flag
        
    def get_tag(self, name):
        for t in self.tags:
            if t.name == name:
                return t
        return None

    def get_raw_packet(self):
        if self.accept_flags != EC_FLAG_BLANK:
            self.set_flag(EC_FLAG_ACCEPTS)
            headdata = "\x00\x00" + struct.pack("BB", self.flags, self.accept_flags)
        else:
            headdata = "\x00\x00\x00" + struct.pack("B", self.flags)

        utf8_numbers = self.get_flag(EC_FLAG_UTF8_NUMBERS)
        use_zlib = self.get_flag(EC_FLAG_ZLIB)

        tagdata = ""
        for t in self.tags:
            tagdata = tagdata + t.get_data(utf8_numbers)[0]

        if utf8_numbers:
            utf8_tcount = ec_number_to_utf8(len(self.tags))
            appdata = struct.pack("!B", self.opcode) + utf8_tcount
        else:
            appdata = struct.pack("!BH", self.opcode, len(self.tags))
        appdata = appdata + tagdata

        if use_zlib:
            appdata = zlib.compress(appdata)

        headdata = headdata + struct.pack("!I", len(appdata))
        return headdata + appdata

    def _parse_raw_packet(self, data):
        self._read_raw_packet(StringIO(data))

    def _read_raw_packet(self, dbuf):
        self.flags, msg_len = struct.unpack("!II", dbuf.read(8))

        if self.get_flag(EC_FLAG_ACCEPTS):
            self.accept_flags = (self.flags & 0xFF00 ) >> 8

        utf8_numbers = self.get_flag(EC_FLAG_UTF8_NUMBERS)
        use_zlib = self.get_flag(EC_FLAG_ZLIB)

        if use_zlib:
            data = zlib.decompress(dbuf.read(msg_len))
            dbuf = StringIO(data)

        self.opcode = struct.unpack("!B", dbuf.read(1))[0]

        if utf8_numbers:
            tagcount = ec_read_utf8(dbuf)
        else:
            tagcount = struct.unpack("!H", dbuf.read(2))[0]

        def parse_tag(buf, utf8_numbers):
            if utf8_numbers:
                tagname = ec_read_utf8(buf)
                tagtype = struct.unpack("!B", buf.read(1))[0]
                taglen = ec_read_utf8(buf)
            else:
                tagname, tagtype, taglen = struct.unpack("!HBI", buf.read(7))

            has_subtags = tagname & 0x1
            tagname = tagname >> 1
            subtags = []

            if has_subtags:
                if utf8_numbers:
                    subtagcount = ec_read_utf8(buf)
                else:
                    subtagcount = struct.unpack("!H", buf.read(2))[0]

                for j in range(subtagcount):
                    subtags.append(parse_tag(buf, utf8_numbers))

            if tagtype == EC_TAGTYPE_CUSTOM:
                string = buf.read(taglen)
                tag = ECCustomTag(string, tagname)
            elif tagtype == EC_TAGTYPE_UINT8:
                tag = ECUInt8Tag(struct.unpack("!B", buf.read(1))[0], tagname)
            elif tagtype == EC_TAGTYPE_UINT16:
                tag = ECUInt16Tag(struct.unpack("!H", buf.read(2))[0], tagname)
            elif tagtype == EC_TAGTYPE_UINT32:
                tag = ECUInt32Tag(struct.unpack("!I", buf.read(4))[0], tagname)
            elif tagtype == EC_TAGTYPE_UINT64:
                tag = ECUInt64Tag(struct.unpack("!Q", buf.read(8))[0], tagname)
            elif tagtype == EC_TAGTYPE_STRING:
                string = ""
                while 1:
                    char = buf.read(1)
                    if char == "\x00":
                        break
                    else:
                        string = string + char
                tag = ECStringTag(string, tagname)
            elif tagtype == EC_TAGTYPE_DOUBLE:
                tag = ECDoubleTag(struct.unpack("!d", buf.read(8))[0], tagname)
            elif tagtype == EC_TAGTYPE_HASH16:
                raw = buf.read(16)
                val = ''.join(["%02x" % x for x in struct.unpack("!16B", raw)])
                tag = ECHash16Tag(val, tagname)
            else:
                raise ECUnknownTagtypeError("Unsupported TagType: 0x%x" % tagtype)

            tag.subtags = subtags
            return tag

        for i in range(tagcount):
            self.tags.append(parse_tag(dbuf, utf8_numbers))

    def dump(self, with_raw = False):
        s = "Flags: 0x%02x\n" % self.flags
        if self.get_flag(EC_FLAG_ACCEPTS):
            s = s + "Accept flags: 0x%02x\n" % self.accept_flags
        s = s + "Opcode: 0x%02x (%s)\n" % (self.opcode, ec_opcode_str(self.opcode))
        s = s + "Tag count: %d\n" % len(self.tags)
        s = s + "\nTags:\n\n"

        for t in self.tags:
            s = s + t.dump() + "\n"

        if with_raw:
            s = s + "\nRaw data:\n"
            raw = self.get_raw_packet()
            cnt = 0
            for c in raw:
                s = s + "%02x" % ord(c)
                if cnt % 4 == 3:
                    s = s + " "
                if cnt % 16 == 15:
                    s = s + "\n"
                cnt = cnt + 1

        return s

