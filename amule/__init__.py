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

from eccodes import EC_KNOWN_VERSIONS, ECCodes 
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

    #
    # Connection and socket handling
    #

    def __init__(self):
        self._reset()

    def _reset(self):
        """Reset client state
        
        The main goal of this is to turn IO buffers into something that raises
        a neat exception when IO calls are made on them.
        
        """
        
        self.codes = None
        self.protocol_version = None
        self.server_version = None
        self._socket = None
        self._wfile = _NotConnectedFile()
        self._rfile = _NotConnectedFile()

    def _writepacket(self, packet):
        """Send a packet to amuled"""
        self._wfile.write(packet.get_raw_packet(self.codes))
        self._wfile.flush()
        
    def _readpacket(self):
        """Receive a packet from amuled"""
        return ECPacket(self.codes, buffer = self._rfile)
        
    def _authenticate(self, password, client_name, client_version):
        """Authenticate with amuled
        
        Send a first packet to request authentication (with client_name,
        client_version and protocol version).  Send a second packet with the
        hashed password salted with a salt value returned in the response to
        the first packet.
        
        Return True/False and fill self.server_version from the response to the
        second packet.
        
        """
        
        connected = False
        for vers in EC_KNOWN_VERSIONS:
            self.protocol_version = vers
            self.codes = ECCodes(vers)
        
            pass_md5 = hashlib.md5(password).hexdigest()
            req_packet = ECPacket(self.codes, opcode = self.codes.OP_AUTH_REQ)
            req_packet.tags.extend([
                ECStringTag(client_name, self.codes.TAG_CLIENT_NAME),
                ECStringTag(client_version, self.codes.TAG_CLIENT_VERSION),
                ECUInt16Tag(vers, self.codes.TAG_PROTOCOL_VERSION)
            ])
            
            if vers < 0x0203:
                req_packet.tags.append(
                    ECHash16Tag(pass_md5, self.codes.TAG_PASSWD_HASH)
                )
                self._writepacket(req_packet)
            else:
                self._writepacket(req_packet)
                resp = self._readpacket()
                
                if resp.opcode != self.codes.OP_AUTH_SALT:
                    continue
                try:
                    salt = resp.get_tag(self.codes.TAG_PASSWD_SALT).value
                except AttributeError:
                    continue
                    
                salt_md5 = hashlib.md5("%lX" % salt).hexdigest()
                pass_salt = hashlib.md5(pass_md5.lower() + salt_md5).hexdigest()
                
                pass_packet = ECPacket(self.codes, opcode = self.codes.OP_AUTH_PASSWD)
                pass_packet.tags.extend([
                    ECHash16Tag(pass_salt, self.codes.TAG_PASSWD_HASH)
                ])
                self._writepacket(pass_packet)
                
            resp = self._readpacket()            
            if resp.opcode != self.codes.OP_AUTH_OK:
                continue
            try:
                self.server_version = resp.get_tag(self.codes.TAG_SERVER_VERSION).value
            except AttributeError:
                self.server_version = 'unknown'
            connected = True
            break
            
        return connected

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
            ret = self._authenticate(password, client_name, client_version)
        except:
            self.disconnect()
            raise
        else:
            if not ret:
                self.disconnect()
                raise ECConnectionError("Authentication failed.")

    def disconnect(self):
        """Disconnect from amuled
        
        Close connection socket and reset the client status.
        
        """
        
        self._wfile.close()
        self._rfile.close()
        self._socket.close()
        self._reset()
        
    #
    # Private packet decoders
    #
        
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
                        if isinstance(item_map[st.name], list):
                            key, tagname = item_map[st.name]
                            item[key] = []
                            for sst in st.subtags:
                                if sst.name == tagname:
                                    item[key].append(sst.value)                                    
                        else:
                            item[item_map[st.name]] = st.value
                items[t.value] = item
                
        ret['items'] = items
        return ret
     
    #
    # Status requests
    #
        
    def get_server_status(self):
        """Get status variables from amuled"""
        req_packet = ECPacket(self.codes, opcode = self.codes.OP_STAT_REQ)
        req_packet.tags.append(ECUInt8Tag(self.codes.DETAIL_CMD, self.codes.TAG_DETAIL_LEVEL))
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        ret = self._linear_decoder(resp,
            [self.codes.OP_STATS],
            {
                self.codes.TAG_STATS_UL_SPEED: 'ul_speed',
                self.codes.TAG_STATS_DL_SPEED: 'dl_speed',
                self.codes.TAG_STATS_UL_SPEED_LIMIT: 'ul_speed_limit',
                self.codes.TAG_STATS_DL_SPEED_LIMIT: 'dl_speed_limit',
                self.codes.TAG_STATS_UL_QUEUE_LEN: 'ul_queue_len',
                self.codes.TAG_STATS_TOTAL_SRC_COUNT: 'total_src_count',
                self.codes.TAG_STATS_ED2K_USERS: 'ed2k_users',
                self.codes.TAG_STATS_KAD_USERS: 'kad_users',
                self.codes.TAG_STATS_ED2K_FILES: 'ed2k_files',
                self.codes.TAG_STATS_KAD_FILES: 'kad_files',
                self.codes.TAG_STATS_KAD_FIREWALLED_UDP: 'kad_firewalled_udp',
                self.codes.TAG_STATS_KAD_INDEXED_SOURCES: 'kad_indexed_sources',
                self.codes.TAG_STATS_KAD_INDEXED_KEYWORDS: 'kad_indexed_keywords',
                self.codes.TAG_STATS_KAD_INDEXED_NOTES: 'kad_indexed_notes',
                self.codes.TAG_STATS_KAD_INDEXED_LOAD: 'kad_indexed_load',
                self.codes.TAG_STATS_KAD_IP_ADRESS: 'kad_ip_address',
                self.codes.TAG_STATS_BUDDY_STATUS: 'buddy_status',
                self.codes.TAG_STATS_BUDDY_IP: 'buddy_ip',
                self.codes.TAG_STATS_BUDDY_PORT: 'buddy_port',
                self.codes.TAG_CONNSTATE: 'connstate'
            }
        )
        
        del(ret['ok'])
        ret['client_id'] = resp.get_tag(self.codes.TAG_CONNSTATE).get_subtag(self.codes.TAG_CLIENT_ID).value
        return ret

    #
    # Search requests
    #
        
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
        req_packet = ECPacket(self.codes, opcode = self.codes.OP_SEARCH_START)
        req_packet.set_flag(self.codes.FLAG_UTF8_NUMBERS)
        tag = ECUInt8Tag(method, self.codes.TAG_SEARCH_TYPE)
        subtags = [ECStringTag(query, self.codes.TAG_SEARCH_NAME)]
        if minsize is not None:
            subtags.append(ECUInt32Tag(minsize, self.codes.TAG_SEARCH_MIN_SIZE))
        if maxsize is not None:
            subtags.append(ECUInt32Tag(maxsize, self.codes.TAG_SEARCH_MAX_SIZE))
        subtags.append(ECStringTag(type, self.codes.TAG_SEARCH_FILE_TYPE))
        if ext is not None:
            subtags.append(ECStringTag(ext, self.codes.TAG_SEARCH_EXTENSION))
        if avail is not None:
            subtags.append(ECUInt32Tag(avail, self.codes.TAG_SEARCH_AVAILABILITY))
        tag.subtags.extend(subtags)
        req_packet.tags.append(tag)
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        return self._linear_decoder(resp,
            [self.codes.OP_FAILED],
            {self.codes.TAG_STRING: 'message'}
        )
        
    def get_search_progress(self):
        """Get search progress from amuled
        
        Return search progress percent.  Does not work for Kad searches (always
        returns 0).
        
        """
    
        req_packet = ECPacket(self.codes, opcode = self.codes.OP_SEARCH_PROGRESS)
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        return resp.get_tag(self.codes.TAG_SEARCH_STATUS).value
        
    def get_search_results(self, update = False):
        """Get search results from amuled
        
        Return a dict() with hashes as keys, each value being a dict() with the
        following keys:
        - 'name': file name
        - 'size': file size in bytes
        - 'src_count': seed count
        - 'src_count_xfer': transferring seed count
          
        When update is True, only new results are filled, and changed results
        (eg. additional seeds found) only have changed keys filled.  All result
        hashes are present, though.  'new' and 'changed' refer to the last time
        search results were fetched from amuled.
        
        """
        req_packet = ECPacket(self.codes, opcode = self.codes.OP_SEARCH_RESULTS)
        if update:
            req_packet.tags.append(ECUInt8Tag(self.codes.DETAIL_INC_UPDATE,
                                                self.codes.TAG_DETAIL_LEVEL))
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        return self._list_decoder(resp,
            [self.codes.OP_SEARCH_RESULTS],
            self.codes.TAG_SEARCHFILE,
            {
                self.codes.TAG_PARTFILE_SOURCE_COUNT: 'src_count',
                self.codes.TAG_PARTFILE_SOURCE_COUNT_XFER: 'src_count_xfer',
                self.codes.TAG_PARTFILE_NAME: 'name',
                self.codes.TAG_PARTFILE_SIZE_FULL: 'size'
            }
        )['items']
     
    #
    # Download list
    #
        
    def download_search_results(self, hashes, category = 0):
        req_packet = ECPacket(self.codes, opcode = self.codes.OP_DOWNLOAD_SEARCH_RESULT)
        for h in hashes:
            tag = ECHash16Tag(h, self.codes.TAG_SEARCHFILE)
            tag.subtags.append(ECUInt8Tag(category, self.codes.TAG_CATEGORY))
            req_packet.tags.append(tag)
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        # aMule response does not indicate success or failure (yet?)
        return True

    def download_ed2klinks(self, links, category = 0):
        req_packet = ECPacket(self.codes, opcode = self.codes.OP_ADD_LINK)
        for l in links:
            tag = ECStringTag(l, self.codes.TAG_STRING)
            tag.subtags.append(ECUInt8Tag(category, self.codes.TAG_CATEGORY))
            req_packet.tags.append(tag)
            
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        if resp.opcode == self.codes.OP_NOOP:
            return True
        else:
            return False
        
    def get_download_list(self, detail = False, update = False):
        if detail:
            req_packet = ECPacket(self.codes, opcode = self.codes.OP_GET_DLOAD_QUEUE_DETAIL)
            req_packet.tags.append(ECUInt8Tag(self.codes.DETAIL_FULL,
                                                    self.codes.TAG_DETAIL_LEVEL))
        else:
            req_packet = ECPacket(self.codes, opcode = self.codes.OP_GET_DLOAD_QUEUE)
            if update:
                req_packet.tags.append(ECUInt8Tag(self.codes.DETAIL_INC_UPDATE,
                                                    self.codes.TAG_DETAIL_LEVEL))
        self._writepacket(req_packet)
        resp = self._readpacket()

        mapping = {
            self.codes.TAG_PARTFILE_STATUS: 'status',
            self.codes.TAG_PARTFILE_SOURCE_COUNT: 'src_count',
            self.codes.TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT: 'src_count_not_current',
            self.codes.TAG_PARTFILE_SOURCE_COUNT_XFER: 'src_count_xfer',
            self.codes.TAG_PARTFILE_SOURCE_COUNT_A4AF: 'src_count_a4af',
            self.codes.TAG_PARTFILE_NAME: 'name',
            self.codes.TAG_PARTFILE_SIZE_XFER: 'size_xfer',
            self.codes.TAG_PARTFILE_SIZE_DONE: 'size_done',
            self.codes.TAG_PARTFILE_SIZE_FULL: 'size',
            self.codes.TAG_PARTFILE_SPEED: 'speed',
            self.codes.TAG_PARTFILE_PRIO: 'prio',
            self.codes.TAG_PARTFILE_CAT: 'cat',
            self.codes.TAG_PARTFILE_LAST_SEEN_COMP: 'last_seen_comp',
            self.codes.TAG_PARTFILE_LAST_RECV: 'last_recv',
            self.codes.TAG_PARTFILE_PARTMETID: 'partmetid',
            self.codes.TAG_PARTFILE_ED2K_LINK: 'ed2k_link',
            self.codes.TAG_PARTFILE_SOURCE_NAMES: ['source_names', self.codes.TAG_PARTFILE_SOURCE_NAMES]
        }
        
        if self.protocol_version >= 0x0203:
            mapping.extend({
                self.codes.TAG_PARTFILE_LOST_CORRUPTION: 'lost_corruption',
                self.codes.TAG_PARTFILE_GAINED_COMPRESSION: 'gained_compression',
                self.codes.TAG_PARTFILE_SAVED_ICH: 'saved_ich',
                self.codes.TAG_PARTFILE_STOPPED: 'stopped',
                self.codes.TAG_PARTFILE_DOWNLOAD_ACTIVE: 'download_active'
            })
        
        return self._list_decoder(resp,
            [self.codes.OP_DLOAD_QUEUE],
            self.codes.TAG_PARTFILE,
            mapping
        )['items']
        
    #
    # Downloading files handling
    #

    def _partfile_cmd(self, hashes, opcode, arg = None):
        """Send a partfile command to amuled
        
        A same command can hold multiple hashes (ie target multiple partfiles).
        If arg is present (must be a ECTag), it is added to every partfile.
        
        Returns True/False on success/failure.
        
        """
        
        req_packet = ECPacket(self.codes, opcode = opcode)
        for h in hashes:
            tag = ECHash16Tag(h, self.codes.TAG_PARTFILE)
            if arg is not None:
                tag.subtags.append(arg)
            req_packet.tags.append(tag)
            
        self._writepacket(req_packet)
        resp = self._readpacket()
        
        if resp.opcode == self.codes.OP_NOOP:
            return True
        else:
            return False
        
    def partfile_remove_noneed(self, hashes):
        """Remove not needed sources from partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_REMOVE_NO_NEEDED)
        
    def partfile_remove_fullqueue(self, hashes):
        """Remove sources with a full UL queue from partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_REMOVE_FULL_QUEUE)
        
    def partfile_remove_highqueue(self, hashes):
        """Remove sources with a high UL queue from partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_REMOVE_HIGH_QUEUE)
        
    def partfile_cleanup_sources(self, hashes):
        """Clean up sources from partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_CLEANUP_SOURCES)
        
    def partfile_swap_a4af_this(self, hashes):
        """Swap A4AF sources to these partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_SWAP_A4AF_THIS)
        
    def partfile_swap_a4af_this_auto(self, hashes):
        """Automatically swap A4AF sources to these partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_SWAP_A4AF_THIS_AUTO)
        
    def partfile_swap_a4af_others(self, hashes):
        """Swap A4AF sources of partfiles to other partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_SWAP_A4AF_OTHERS)
        
    def partfile_pause(self, hashes):
        """Pause partfiles download"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_PAUSE)
        
    def partfile_resume(self, hashes):
        """Resume partfiles download"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_RESUME)
        
    def partfile_stop(self, hashes):
        """Stop partfiles download"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_STOP)
        
    def partfile_delete(self, hashes):
        """Delete partfiles"""
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_DELETE)
        
    def partfile_set_prio(self, hashes, prio):
        """Set partfiles priority"""
        arg = ECUInt8Tag(prio, self.codes.TAG_PARTFILE_PRIO)
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_PRIO_SET, arg)
        
    def partfile_set_cat(self, hashes, cat = 0):
        """Set partfiles category"""
        arg = ECUInt8Tag(cat, self.codes.TAG_PARTFILE_CAT)
        return self._partfile_cmd(hashes, self.codes.OP_PARTFILE_SET_CAT, arg)
        
