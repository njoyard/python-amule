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

__all__ = ['eccodes', 'ectag', 'ecpacket', 'ecpacketutils']

import hashlib
import socket

from eccodes import *
from ectag import *
from ecpacket import ECPacket


class ECError(Exception): pass
class ECConnectionError(ECError): pass

class _NotConnectedFile:
    def __getattr__(self, attr):
        return self._dummy

    def _dummy(*args):
        raise ECConnectionError("Not connected")

class AmuleClient:

    def __init__(self):
        self._reset()

    def _reset(self):
        """Reset client state
        
        The main goal of this is to turn IO buffers into something that raises
        a neat exception when IO calls are made on them.
        
        """
        
        self.server_version = None
        self._socket = None
        self._wfile = _NotConnectedFile()
        self._rfile = _NotConnectedFile()

    def _writepacket(self, packet):
        """Send a packet to amuled"""
        self._wfile.write(packet.get_raw_packet())
        self._wfile.flush()
        
    def _readpacket(self):
        """Receive a packet from amuled"""
        return ECPacket(buffer = self._rfile)

    def _linear_decoder(self, packet, ok_opcodes, tag_map):
        """Linear packet decoder
        
        Decode packet into a dict() containing:
        - 'ok':True if the packet opcode is in ok_opcodes, 'ok':False if not
        - an item for each tag_map.keys() that is a tagname found in the packet
          with tag_map[tagname] as the key and the tag value as the value
          
        """
    
        ret = {'ok': False}
        if packet.opcode in ok_opcodes:
            ret['ok'] = True

        for t in packet.tags:
            if tag_map.has_key(t.name):
                ret[tag_map[t.name]] = t.value

        return ret
        
    def _list_decoder(self, packet, ok_opcodes, item_tag, item_map):
        """List packet decoder
        
        Decode packet into a dict() containing:
        - an 'ok' item as in _linear_decoder
        - a 'items' item which is in turn a dict().
        
        'items' keys are values from the packet tags with tagname item_tag, and
        each is filled like _linear_decoder does using item_map.
        
        """
    
        ret = {'ok': False}
        if packet.opcode in ok_opcodes:
            ret['ok'] = True
            
        items = dict()
        for t in packet.tags:
            if t.name == item_tag:
                item = dict()
                for st in t.subtags:
                    if item_map.has_key(st.name):
                        item[item_map[st.name]] = st.value
                items[t.value] = item
                
        ret['items'] = items
        return ret
        
    def _authenticate(self, password, client_name, client_version):
        """Authenticate with amuled
        
        Send a first packet to request authentication (with client_name,
        client_version and protocol version).  Send a second packet with the
        hashed password salted with a salt value returned in the response to
        the first packet.
        
        Return True/False and fill self.server_version from the response to the
        second packet.
        
        """
        
        req_packet = ECPacket(opcode = EC_OP_AUTH_REQ)
        req_packet.tags.extend([
            ECStringTag(client_name, EC_TAG_CLIENT_NAME),
            ECStringTag(client_version, EC_TAG_CLIENT_VERSION),
            ECUInt16Tag(EC_CURRENT_PROTOCOL_VERSION, EC_TAG_PROTOCOL_VERSION)
        ])
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        if resp.opcode != EC_OP_AUTH_SALT:
            return False
        try:
            salt = resp.get_tag(EC_TAG_PASSWD_SALT).value
        except AttributeError:
            return False
            
        salt_md5 = hashlib.md5("%lX" % salt).hexdigest()
        pass_md5 = hashlib.md5(password).hexdigest()
        pass_salt = hashlib.md5(pass_md5.lower() + salt_md5).hexdigest()
        
        pass_packet = ECPacket(opcode = EC_OP_AUTH_PASSWD)
        pass_packet.tags.extend([
            ECHash16Tag(pass_salt, EC_TAG_PASSWD_HASH)
        ])
        self._writepacket(pass_packet)
        resp = self._readpacket()
        
        if resp.opcode != EC_OP_AUTH_OK:
            return False
        try:
            self.server_version = resp.get_tag(EC_TAG_SERVER_VERSION).value
        except AttributeError:
            self.server_version = 'unknown'
        return True

    def connect(self, host, port, password,
                client_name = '', client_version = ''):
        """Attempt connection to amuled
        
        Try to create a socket with amuled, as well as read/write buffers from
        this socket.  When successful, run authenticate handshake with amuled.
        
        Raises ECConnectionError or socket.error on failure.
        
        """
        
        if self._socket:
            raise ECConnectionError("Already connected")

        try:
            flags = socket.AI_ADDRCONFIG
        except AttributeError:
            flags = 0

        msg = "getaddrinfo returned nothing"
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                socket.SOCK_STREAM, socket.IPPROTO_TCP, flags):
            af, stype, proto, cname, sa = res
            try:
                self._socket = socket.socket(af, stype, proto)
                self._socket.connect(sa)
            except socket.error, msg:
                if self._socket:
                    self._socket.close()
                    self._socket = None
                continue
            break

        if not self._socket:
            raise socket.error(msg)

        self._wfile = self._socket.makefile("wb")
        self._rfile = self._socket.makefile("rb")

        try:
            if not self._authenticate(password, client_name, client_version):
                self.disconnect()
                raise ECConnectionError("Authentication failed.")
        except:
            self.disconnect()
            raise

    def disconnect(self):
        """Disconnect from amuled
        
        Close connection socket and reset the client status.
        
        """
        
        self._wfile.close()
        self._rfile.close()
        self._socket.close()
        self._reset()
        
    def get_server_status(self):
        req_packet = ECPacket(opcode = EC_OP_STAT_REQ)
        req_packet.tags.append(ECUInt8Tag(EC_DETAIL_CMD, EC_TAG_DETAIL_LEVEL))
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        ret = self._linear_decoder(resp,
            [EC_OP_STATS],
            {
                EC_TAG_STATS_UL_SPEED: 'ul_speed',
                EC_TAG_STATS_DL_SPEED: 'dl_speed',
                EC_TAG_STATS_UL_SPEED_LIMIT: 'ul_speed_limit',
                EC_TAG_STATS_DL_SPEED_LIMIT: 'dl_speed_limit',
                EC_TAG_STATS_UL_QUEUE_LEN: 'ul_queue_len',
                EC_TAG_STATS_TOTAL_SRC_COUNT: 'total_src_count',
                EC_TAG_STATS_ED2K_USERS: 'ed2k_users',
                EC_TAG_STATS_KAD_USERS: 'kad_users',
                EC_TAG_STATS_ED2K_FILES: 'ed2k_files',
                EC_TAG_STATS_KAD_FILES: 'kad_files',
                EC_TAG_STATS_KAD_FIREWALLED_UDP: 'kad_firewalled_udp',
                EC_TAG_STATS_KAD_INDEXED_SOURCES: 'kad_indexed_sources',
                EC_TAG_STATS_KAD_INDEXED_KEYWORDS: 'kad_indexed_keywords',
                EC_TAG_STATS_KAD_INDEXED_NOTES: 'kad_indexed_notes',
                EC_TAG_STATS_KAD_INDEXED_LOAD: 'kad_indexed_load',
                EC_TAG_STATS_KAD_IP_ADRESS: 'kad_ip_address',
                EC_TAG_STATS_BUDDY_STATUS: 'buddy_status',
                EC_TAG_STATS_BUDDY_IP: 'buddy_ip',
                EC_TAG_STATS_BUDDY_PORT: 'buddy_port',
                EC_TAG_CONNSTATE: 'connstate'
            }
        )
        
        del(ret['ok'])
        ret['client_id'] = resp.get_tag(EC_TAG_CONNSTATE).get_subtag(EC_TAG_CLIENT_ID).value
        return ret
        
    def search_start(self, query, method, minsize = None, maxsize = None,
                        type = '', avail = None, ext = None):
        """Send a search start request to amuled
        
        query:   full text search query
        method:  0 (local), 1 (global) or 2 (kad)
        minsize: min file size in bytes or None
        maxsize: max file size in bytes or None
        type:    amule file type, empty string or one of:
                 Audio, Videos, Texts, Programs, CD-Images, Archives
        avail:   min seed number or None
        ext:     file extension or None
        
        Return a dict() with two keys:
        - 'ok': True or False
        - 'message': reason for 'ok', as told by amuled
        
        """
        req_packet = ECPacket(opcode = EC_OP_SEARCH_START)
        req_packet.set_flag(EC_FLAG_UTF8_NUMBERS)
        tag = ECUInt8Tag(method, EC_TAG_SEARCH_TYPE)
        subtags = [ECStringTag(query, EC_TAG_SEARCH_NAME)]
        if minsize is not None:
            subtags.append(ECUInt32Tag(minsize, EC_TAG_SEARCH_MIN_SIZE))
        if maxsize is not None:
            subtags.append(ECUInt32Tag(maxsize, EC_TAG_SEARCH_MAX_SIZE))
        subtags.append(ECStringTag(type, EC_TAG_SEARCH_FILE_TYPE))
        if ext is not None:
            subtags.append(ECStringTag(ext, EC_TAG_SEARCH_EXTENSION))
        if avail is not None:
            subtags.append(ECUInt32Tag(avail, EC_TAG_SEARCH_AVAILABILITY))
        tag.subtags.extend(subtags)
        req_packet.tags.append(tag)
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        return self._linear_decoder(resp,
            [EC_OP_FAILED],
            {EC_TAG_STRING: 'message'}
        )
        
    def get_search_progress(self):
        """Get search progress from amuled
        
        Return search progress percent.  Does not work for Kad searches (always
        returns 0).
        
        """
    
        req_packet = ECPacket(opcode = EC_OP_SEARCH_PROGRESS)
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        return resp.get_tag(EC_TAG_SEARCH_STATUS).value
        
    def get_search_results(self, update = False):
        """Get search results from amuled
        
        Return a dict() with hashes as keys, each value being a dict() with the
        following keys:
        - 'name': file name
        - 'size': file size in bytes
        - 'src_count': seed count
        - 'src_count_xfer': transferring seed count (for already downloading
          files)
          
        When update is True, only new results are filled, and changed results
        (eg. additional seeds found) only have changed keys filled. All result
        hashes are present, though.
        
        """
        req_packet = ECPacket(opcode = EC_OP_SEARCH_RESULTS)
        if update:
            req_packet.tags.append(ECUInt8Tag(EC_DETAIL_INC_UPDATE,
                                                EC_TAG_DETAIL_LEVEL))
        self._writepacket(req_packet)
        resp = self._readpacket()
        return self._list_decoder(resp,
            [EC_OP_SEARCH_RESULTS],
            EC_TAG_SEARCHFILE,
            {
                EC_TAG_PARTFILE_SOURCE_COUNT: 'src_count',
                EC_TAG_PARTFILE_SOURCE_COUNT_XFER: 'src_count_xfer',
                EC_TAG_PARTFILE_NAME: 'name',
                EC_TAG_PARTFILE_SIZE_FULL: 'size'
            }
        )['items']

