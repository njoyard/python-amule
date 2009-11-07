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

# Tag types
EC_TAGTYPE_UNKNOWN = 0
EC_TAGTYPE_CUSTOM = 1
EC_TAGTYPE_UINT8 = 2
EC_TAGTYPE_UINT16 = 3
EC_TAGTYPE_UINT32 = 4
EC_TAGTYPE_UINT64 = 5
EC_TAGTYPE_STRING = 6
EC_TAGTYPE_DOUBLE = 7
EC_TAGTYPE_IPV4 = 8
EC_TAGTYPE_HASH16 = 9

# Detail levels
EC_DETAIL_CMD           = 0x00
EC_DETAIL_WEB           = 0x01
EC_DETAIL_FULL          = 0x02
EC_DETAIL_UPDATE        = 0x03
EC_DETAIL_INC_UPDATE    = 0x04

# Partfile statuses
EC_PS_READY            = 0
EC_PS_EMPTY            = 1
EC_PS_WAITINGFORHASH   = 2
EC_PS_HASHING          = 3
EC_PS_ERROR            = 4
EC_PS_INSUFFICIENT     = 5
EC_PS_UNKNOWN          = 6
EC_PS_PAUSED           = 7
EC_PS_COMPLETING       = 8
EC_PS_COMPLETE         = 9
EC_PS_ALLOCATING       = 10

# Partfile priorities
EC_PR_VERYLOW          = 4 
EC_PR_LOW              = 0
EC_PR_NORMAL           = 1
EC_PR_HIGH             = 2 
EC_PR_VERYHIGH         = 3
EC_PR_AUTO             = 5
EC_PR_POWERSHARE       = 6

EC_KNOWN_VERSIONS = [0x0200, 0x0203]

class ECVersionError(Exception): pass

class ECCodes:

    def __init__(self, version):
        if version not in EC_KNOWN_VERSIONS:
            raise ECVersionError("Unknown protocol version: 0x%04x" % version)

        # Protocol version
        self.CURRENT_PROTOCOL_VERSION = version
        
        # Flags
        self.FLAG_BLANK         = 0x20
        self.FLAG_ZLIB          = 0x01
        self.FLAG_UTF8_NUMBERS  = 0x02
        self.FLAG_HAS_ID        = 0x04
        self.FLAG_ACCEPTS       = 0x10
        self.FLAG_EXTENSION     = 0x80

        # Opcodes
        self.OP_NOOP                          = 0x01
        self.OP_AUTH_REQ                      = 0x02
        self.OP_AUTH_FAIL                     = 0x03
        self.OP_AUTH_OK                       = 0x04
        self.OP_FAILED                        = 0x05
        self.OP_STRINGS                       = 0x06
        self.OP_MISC_DATA                     = 0x07
        self.OP_SHUTDOWN                      = 0x08
        self.OP_ADD_LINK                      = 0x09
        self.OP_STAT_REQ                      = 0x0A
        self.OP_GET_CONNSTATE                 = 0x0B
        self.OP_STATS                         = 0x0C
        self.OP_GET_DLOAD_QUEUE               = 0x0D
        self.OP_GET_ULOAD_QUEUE               = 0x0E
        self.OP_GET_WAIT_QUEUE                = 0x0F
        self.OP_GET_SHARED_FILES              = 0x10
        self.OP_SHARED_SET_PRIO               = 0x11
        self.OP_PARTFILE_REMOVE_NO_NEEDED     = 0x12
        self.OP_PARTFILE_REMOVE_FULL_QUEUE    = 0x13
        self.OP_PARTFILE_REMOVE_HIGH_QUEUE    = 0x14
        self.OP_PARTFILE_CLEANUP_SOURCES      = 0x15
        self.OP_PARTFILE_SWAP_A4AF_THIS       = 0x16
        self.OP_PARTFILE_SWAP_A4AF_THIS_AUTO  = 0x17
        self.OP_PARTFILE_SWAP_A4AF_OTHERS     = 0x18
        self.OP_PARTFILE_PAUSE                = 0x19
        self.OP_PARTFILE_RESUME               = 0x1A
        self.OP_PARTFILE_STOP                 = 0x1B
        self.OP_PARTFILE_PRIO_SET             = 0x1C
        self.OP_PARTFILE_DELETE               = 0x1D
        self.OP_PARTFILE_SET_CAT              = 0x1E
        self.OP_DLOAD_QUEUE                   = 0x1F
        self.OP_ULOAD_QUEUE                   = 0x20
        self.OP_WAIT_QUEUE                    = 0x21
        self.OP_SHARED_FILES                  = 0x22
        self.OP_SHAREDFILES_RELOAD            = 0x23
        self.OP_SHAREDFILES_ADD_DIRECTORY     = 0x24
        self.OP_RENAME_FILE                   = 0x25
        self.OP_SEARCH_START                  = 0x26
        self.OP_SEARCH_STOP                   = 0x27
        self.OP_SEARCH_RESULTS                = 0x28
        self.OP_SEARCH_PROGRESS               = 0x29
        self.OP_DOWNLOAD_SEARCH_RESULT        = 0x2A
        self.OP_IPFILTER_RELOAD               = 0x2B
        self.OP_GET_SERVER_LIST               = 0x2C
        self.OP_SERVER_LIST                   = 0x2D
        self.OP_SERVER_DISCONNECT             = 0x2E
        self.OP_SERVER_CONNECT                = 0x2F
        self.OP_SERVER_REMOVE                 = 0x30
        self.OP_SERVER_ADD                    = 0x31
        self.OP_SERVER_UPDATE_FROM_URL        = 0x32
        self.OP_ADDLOGLINE                    = 0x33
        self.OP_ADDDEBUGLOGLINE               = 0x34
        self.OP_GET_LOG                       = 0x35
        self.OP_GET_DEBUGLOG                  = 0x36
        self.OP_GET_SERVERINFO                = 0x37
        self.OP_LOG                           = 0x38
        self.OP_DEBUGLOG                      = 0x39
        self.OP_SERVERINFO                    = 0x3A
        self.OP_RESET_LOG                     = 0x3B
        self.OP_RESET_DEBUGLOG                = 0x3C
        self.OP_CLEAR_SERVERINFO              = 0x3D
        self.OP_GET_LAST_LOG_ENTRY            = 0x3E
        self.OP_GET_PREFERENCES               = 0x3F
        self.OP_SET_PREFERENCES               = 0x40
        self.OP_CREATE_CATEGORY               = 0x41
        self.OP_UPDATE_CATEGORY               = 0x42
        self.OP_DELETE_CATEGORY               = 0x43
        self.OP_GET_STATSGRAPHS               = 0x44
        self.OP_STATSGRAPHS                   = 0x45
        self.OP_GET_STATSTREE                 = 0x46
        self.OP_STATSTREE                     = 0x47
        self.OP_KAD_START                     = 0x48
        self.OP_KAD_STOP                      = 0x49
        self.OP_CONNECT                       = 0x4A
        self.OP_DISCONNECT                    = 0x4B
        self.OP_GET_DLOAD_QUEUE_DETAIL        = 0x4C
        self.OP_KAD_UPDATE_FROM_URL           = 0x4D
        self.OP_KAD_BOOTSTRAP_FROM_IP         = 0x4E
        if version >= 0x0203:
            self.OP_AUTH_SALT                     = 0x4F
            self.OP_AUTH_PASSWD                   = 0x50

        # Tags
        self.TAG_STRING                             = 0x0000
        self.TAG_PASSWD_HASH                        = 0x0001
        self.TAG_PROTOCOL_VERSION                   = 0x0002
        self.TAG_VERSION_ID                         = 0x0003
        self.TAG_DETAIL_LEVEL                       = 0x0004
        self.TAG_CONNSTATE                          = 0x0005
        self.TAG_ED2K_ID                            = 0x0006
        self.TAG_LOG_TO_STATUS                      = 0x0007
        self.TAG_BOOTSTRAP_IP                       = 0x0008
        self.TAG_BOOTSTRAP_PORT                     = 0x0009
        self.TAG_CLIENT_ID                          = 0x000A    
        if version >= 0x0203:
            self.TAG_PASSWD_SALT                        = 0x000B
        self.TAG_CLIENT_NAME                        = 0x0100
        self.TAG_CLIENT_VERSION                     = 0x0101
        self.TAG_CLIENT_MOD                         = 0x0102
        self.TAG_STATS_UL_SPEED                     = 0x0200
        self.TAG_STATS_DL_SPEED                     = 0x0201
        self.TAG_STATS_UL_SPEED_LIMIT               = 0x0202
        self.TAG_STATS_DL_SPEED_LIMIT               = 0x0203
        self.TAG_STATS_UP_OVERHEAD                  = 0x0204
        self.TAG_STATS_DOWN_OVERHEAD                = 0x0205
        self.TAG_STATS_TOTAL_SRC_COUNT              = 0x0206
        self.TAG_STATS_BANNED_COUNT                 = 0x0207
        self.TAG_STATS_UL_QUEUE_LEN                 = 0x0208
        self.TAG_STATS_ED2K_USERS                   = 0x0209
        self.TAG_STATS_KAD_USERS                    = 0x020A
        self.TAG_STATS_ED2K_FILES                   = 0x020B
        self.TAG_STATS_KAD_FILES                    = 0x020C
        if version >= 0x0203:
            self.TAG_STATS_LOGGER_MESSAGE               = 0x020D
            self.TAG_STATS_KAD_FIREWALLED_UDP           = 0x020E
            self.TAG_STATS_KAD_INDEXED_SOURCES          = 0x020F
            self.TAG_STATS_KAD_INDEXED_KEYWORDS         = 0x0210
            self.TAG_STATS_KAD_INDEXED_NOTES            = 0x0211
            self.TAG_STATS_KAD_INDEXED_LOAD             = 0x0212
            self.TAG_STATS_KAD_IP_ADRESS                = 0x0213
            self.TAG_STATS_BUDDY_STATUS                 = 0x0214
            self.TAG_STATS_BUDDY_IP                     = 0x0215
            self.TAG_STATS_BUDDY_PORT                   = 0x0216
        self.TAG_PARTFILE                           = 0x0300
        self.TAG_PARTFILE_NAME                      = 0x0301
        self.TAG_PARTFILE_PARTMETID                 = 0x0302
        self.TAG_PARTFILE_SIZE_FULL                 = 0x0303
        self.TAG_PARTFILE_SIZE_XFER                 = 0x0304
        self.TAG_PARTFILE_SIZE_XFER_UP              = 0x0305
        self.TAG_PARTFILE_SIZE_DONE                 = 0x0306
        self.TAG_PARTFILE_SPEED                     = 0x0307
        self.TAG_PARTFILE_STATUS                    = 0x0308
        self.TAG_PARTFILE_PRIO                      = 0x0309
        self.TAG_PARTFILE_SOURCE_COUNT              = 0x030A
        self.TAG_PARTFILE_SOURCE_COUNT_A4AF         = 0x030B
        self.TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT  = 0x030C
        self.TAG_PARTFILE_SOURCE_COUNT_XFER         = 0x030D
        self.TAG_PARTFILE_ED2K_LINK                 = 0x030E
        self.TAG_PARTFILE_CAT                       = 0x030F
        self.TAG_PARTFILE_LAST_RECV                 = 0x0310
        self.TAG_PARTFILE_LAST_SEEN_COMP            = 0x0311
        self.TAG_PARTFILE_PART_STATUS               = 0x0312
        self.TAG_PARTFILE_GAP_STATUS                = 0x0313
        self.TAG_PARTFILE_REQ_STATUS                = 0x0314
        self.TAG_PARTFILE_SOURCE_NAMES              = 0x0315
        self.TAG_PARTFILE_COMMENTS                  = 0x0316
        if version >= 0x0203:
            self.TAG_PARTFILE_STOPPED                   = 0x0317
            self.TAG_PARTFILE_DOWNLOAD_ACTIVE           = 0x0318
            self.TAG_PARTFILE_LOST_CORRUPTION           = 0x0319
            self.TAG_PARTFILE_GAINED_COMPRESSION        = 0x031A
            self.TAG_PARTFILE_SAVED_ICH                 = 0x031B
        self.TAG_KNOWNFILE                          = 0x0400
        self.TAG_KNOWNFILE_XFERRED                  = 0x0401
        self.TAG_KNOWNFILE_XFERRED_ALL              = 0x0402
        self.TAG_KNOWNFILE_REQ_COUNT                = 0x0403
        self.TAG_KNOWNFILE_REQ_COUNT_ALL            = 0x0404
        self.TAG_KNOWNFILE_ACCEPT_COUNT             = 0x0405
        self.TAG_KNOWNFILE_ACCEPT_COUNT_ALL         = 0x0406
        self.TAG_KNOWNFILE_AICH_MASTERHASH          = 0x0407
        if version >= 0x0203:
            self.TAG_KNOWNFILE_FILENAME                 = 0x0408
        self.TAG_SERVER                             = 0x0500
        self.TAG_SERVER_NAME                        = 0x0501
        self.TAG_SERVER_DESC                        = 0x0502
        self.TAG_SERVER_ADDRESS                     = 0x0503
        self.TAG_SERVER_PING                        = 0x0504
        self.TAG_SERVER_USERS                       = 0x0505
        self.TAG_SERVER_USERS_MAX                   = 0x0506
        self.TAG_SERVER_FILES                       = 0x0507
        self.TAG_SERVER_PRIO                        = 0x0508
        self.TAG_SERVER_FAILED                      = 0x0509
        self.TAG_SERVER_STATIC                      = 0x050A
        self.TAG_SERVER_VERSION                     = 0x050B
        self.TAG_CLIENT                             = 0x0600
        self.TAG_CLIENT_SOFTWARE                    = 0x0601
        self.TAG_CLIENT_SCORE                       = 0x0602
        self.TAG_CLIENT_HASH                        = 0x0603
        self.TAG_CLIENT_FRIEND                      = 0x0604
        self.TAG_CLIENT_WAIT_TIME                   = 0x0605
        self.TAG_CLIENT_XFER_TIME                   = 0x0606
        self.TAG_CLIENT_QUEUE_TIME                  = 0x0607
        self.TAG_CLIENT_LAST_TIME                   = 0x0608
        self.TAG_CLIENT_UPLOAD_SESSION              = 0x0609
        self.TAG_CLIENT_UPLOAD_TOTAL                = 0x060A
        self.TAG_CLIENT_DOWNLOAD_TOTAL              = 0x060B
        self.TAG_CLIENT_STATE                       = 0x060C
        self.TAG_CLIENT_UP_SPEED                    = 0x060D
        self.TAG_CLIENT_DOWN_SPEED                  = 0x060E
        self.TAG_CLIENT_FROM                        = 0x060F
        self.TAG_CLIENT_USER_IP                     = 0x0610
        self.TAG_CLIENT_USER_PORT                   = 0x0611
        self.TAG_CLIENT_SERVER_IP                   = 0x0612
        self.TAG_CLIENT_SERVER_PORT                 = 0x0613
        self.TAG_CLIENT_SERVER_NAME                 = 0x0614
        self.TAG_CLIENT_SOFT_VER_STR                = 0x0615
        self.TAG_CLIENT_WAITING_POSITION            = 0x0616
        if version >= 0x0203:
            self.TAG_CLIENT_IDENT_STATE                 = 0x0617
            self.TAG_CLIENT_OBFUSCATED_CONNECTION       = 0x0618
            self.TAG_CLIENT_RATING                      = 0x0619
            self.TAG_CLIENT_REMOTE_QUEUE_RANK           = 0x061A
            self.TAG_CLIENT_ASKED_COUNT                 = 0x061B
        self.TAG_SEARCHFILE                         = 0x0700
        self.TAG_SEARCH_TYPE                        = 0x0701
        self.TAG_SEARCH_NAME                        = 0x0702
        self.TAG_SEARCH_MIN_SIZE                    = 0x0703
        self.TAG_SEARCH_MAX_SIZE                    = 0x0704
        self.TAG_SEARCH_FILE_TYPE                   = 0x0705
        self.TAG_SEARCH_EXTENSION                   = 0x0706
        self.TAG_SEARCH_AVAILABILITY                = 0x0707
        self.TAG_SEARCH_STATUS                      = 0x0708
        self.TAG_SELECT_PREFS                       = 0x1000
        self.TAG_PREFS_CATEGORIES                   = 0x1100
        self.TAG_CATEGORY                           = 0x1101
        self.TAG_CATEGORY_TITLE                     = 0x1102
        self.TAG_CATEGORY_PATH                      = 0x1103
        self.TAG_CATEGORY_COMMENT                   = 0x1104
        self.TAG_CATEGORY_COLOR                     = 0x1105
        self.TAG_CATEGORY_PRIO                      = 0x1106
        self.TAG_PREFS_GENERAL                      = 0x1200
        self.TAG_USER_NICK                          = 0x1201
        self.TAG_USER_HASH                          = 0x1202
        self.TAG_USER_HOST                          = 0x1203
        self.TAG_PREFS_CONNECTIONS                  = 0x1300
        self.TAG_CONN_DL_CAP                        = 0x1301
        self.TAG_CONN_UL_CAP                        = 0x1302
        self.TAG_CONN_MAX_DL                        = 0x1303
        self.TAG_CONN_MAX_UL                        = 0x1304
        self.TAG_CONN_SLOT_ALLOCATION               = 0x1305
        self.TAG_CONN_TCP_PORT                      = 0x1306
        self.TAG_CONN_UDP_PORT                      = 0x1307
        self.TAG_CONN_UDP_DISABLE                   = 0x1308
        self.TAG_CONN_MAX_FILE_SOURCES              = 0x1309
        self.TAG_CONN_MAX_CONN                      = 0x130A
        self.TAG_CONN_AUTOCONNECT                   = 0x130B
        self.TAG_CONN_RECONNECT                     = 0x130C
        self.TAG_NETWORK_ED2K                       = 0x130D
        self.TAG_NETWORK_KADEMLIA                   = 0x130E
        self.TAG_PREFS_MESSAGEFILTER                = 0x1400
        self.TAG_MSGFILTER_ENABLED                  = 0x1401
        self.TAG_MSGFILTER_ALL                      = 0x1402
        self.TAG_MSGFILTER_FRIENDS                  = 0x1403
        self.TAG_MSGFILTER_SECURE                   = 0x1404
        self.TAG_MSGFILTER_BY_KEYWORD               = 0x1405
        self.TAG_MSGFILTER_KEYWORDS                 = 0x1406
        self.TAG_PREFS_REMOTECTRL                   = 0x1500
        self.TAG_WEBSERVER_AUTORUN                  = 0x1501
        self.TAG_WEBSERVER_PORT                     = 0x1502
        self.TAG_WEBSERVER_GUEST                    = 0x1503
        self.TAG_WEBSERVER_USEGZIP                  = 0x1504
        self.TAG_WEBSERVER_REFRESH                  = 0x1505
        self.TAG_WEBSERVER_TEMPLATE                 = 0x1506
        self.TAG_PREFS_ONLINESIG                    = 0x1600
        self.TAG_ONLINESIG_ENABLED                  = 0x1601
        self.TAG_PREFS_SERVERS                      = 0x1700
        self.TAG_SERVERS_REMOVE_DEAD                = 0x1701
        self.TAG_SERVERS_DEAD_SERVER_RETRIES        = 0x1702
        self.TAG_SERVERS_AUTO_UPDATE                = 0x1703
        self.TAG_SERVERS_URL_LIST                   = 0x1704
        self.TAG_SERVERS_ADD_FROM_SERVER            = 0x1705
        self.TAG_SERVERS_ADD_FROM_CLIENT            = 0x1706
        self.TAG_SERVERS_USE_SCORE_SYSTEM           = 0x1707
        self.TAG_SERVERS_SMART_ID_CHECK             = 0x1708
        self.TAG_SERVERS_SAFE_SERVER_CONNECT        = 0x1709
        self.TAG_SERVERS_AUTOCONN_STATIC_ONLY       = 0x170A
        self.TAG_SERVERS_MANUAL_HIGH_PRIO           = 0x170B
        self.TAG_SERVERS_UPDATE_URL                 = 0x170C
        self.TAG_PREFS_FILES                        = 0x1800
        self.TAG_FILES_ICH_ENABLED                  = 0x1801
        self.TAG_FILES_AICH_TRUST                   = 0x1802
        self.TAG_FILES_NEW_PAUSED                   = 0x1803
        self.TAG_FILES_NEW_AUTO_DL_PRIO             = 0x1804
        self.TAG_FILES_PREVIEW_PRIO                 = 0x1805
        self.TAG_FILES_NEW_AUTO_UL_PRIO             = 0x1806
        self.TAG_FILES_UL_FULL_CHUNKS               = 0x1807
        self.TAG_FILES_START_NEXT_PAUSED            = 0x1808
        self.TAG_FILES_RESUME_SAME_CAT              = 0x1809
        self.TAG_FILES_SAVE_SOURCES                 = 0x180A
        self.TAG_FILES_EXTRACT_METADATA             = 0x180B
        self.TAG_FILES_ALLOC_FULL_SIZE              = 0x180C
        self.TAG_FILES_CHECK_FREE_SPACE             = 0x180D
        self.TAG_FILES_MIN_FREE_SPACE               = 0x180E
        self.TAG_PREFS_SRCDROP                      = 0x1900
        self.TAG_SRCDROP_NONEEDED                   = 0x1901
        self.TAG_SRCDROP_DROP_FQS                   = 0x1902
        self.TAG_SRCDROP_DROP_HQRS                  = 0x1903
        self.TAG_SRCDROP_HQRS_VALUE                 = 0x1904
        self.TAG_SRCDROP_AUTODROP_TIMER             = 0x1905
        self.TAG_PREFS_DIRECTORIES                  = 0x1A00
        if version >= 0x0203:
            self.TAG_DIRECTORIES_INCOMING               = 0x1A01
            self.TAG_DIRECTORIES_TEMP                   = 0x1A02
            self.TAG_DIRECTORIES_SHARED                 = 0x1A03
            self.TAG_DIRECTORIES_SHARE_HIDDEN           = 0x1A04
        self.TAG_PREFS_STATISTICS                   = 0x1B00
        self.TAG_STATSGRAPH_WIDTH                   = 0x1B01
        self.TAG_STATSGRAPH_SCALE                   = 0x1B02
        self.TAG_STATSGRAPH_LAST                    = 0x1B03
        self.TAG_STATSGRAPH_DATA                    = 0x1B04
        self.TAG_STATTREE_CAPPING                   = 0x1B05
        self.TAG_STATTREE_NODE                      = 0x1B06
        self.TAG_STAT_NODE_VALUE                    = 0x1B07
        self.TAG_STAT_VALUE_TYPE                    = 0x1B08
        self.TAG_STATTREE_NODEID                    = 0x1B09
        self.TAG_PREFS_SECURITY                     = 0x1C00
        self.TAG_SECURITY_CAN_SEE_SHARES            = 0x1C01
        self.TAG_IPFILTER_CLIENTS                   = 0x1C02
        self.TAG_IPFILTER_SERVERS                   = 0x1C03
        self.TAG_IPFILTER_AUTO_UPDATE               = 0x1C04
        self.TAG_IPFILTER_UPDATE_URL                = 0x1C05
        self.TAG_IPFILTER_LEVEL                     = 0x1C06
        self.TAG_IPFILTER_FILTER_LAN                = 0x1C07
        self.TAG_SECURITY_USE_SECIDENT              = 0x1C08
        self.TAG_SECURITY_OBFUSCATION_SUPPORTED     = 0x1C09
        self.TAG_SECURITY_OBFUSCATION_REQUESTED     = 0x1C0A
        self.TAG_SECURITY_OBFUSCATION_REQUIRED      = 0x1C0B
        self.TAG_PREFS_CORETWEAKS                   = 0x1D00
        self.TAG_CORETW_MAX_CONN_PER_FIVE           = 0x1D01
        self.TAG_CORETW_VERBOSE                     = 0x1D02
        self.TAG_CORETW_FILEBUFFER                  = 0x1D03
        self.TAG_CORETW_UL_QUEUE                    = 0x1D04
        self.TAG_CORETW_SRV_KEEPALIVE_TIMEOUT       = 0x1D05
        self.TAG_PREFS_KADEMLIA                     = 0x1E00
        self.TAG_KADEMLIA_UPDATE_URL                = 0x1E01


