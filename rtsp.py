# Copyright (C) 2008 David Bern
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

from twisted.web import client
from twisted.internet import defer, reactor
from twisted.python import failure, log
from twisted.protocols import basic
from twisted.python.util import InsensitiveDict
from cStringIO import StringIO
from optparse import OptionParser
from urlparse import urlsplit
import base64
import sys
import math
import time
import struct
from md5 import md5

class rmff_pheader_t:
    """ The contents of this class get inserted
    between RDT data in the output file """
    # Mostly stolen from MPlayer's rmff.c
    object_version = 0
    length = None
    stream_number = 0
    timestamp = None
    reserved = 0
    flags = 0

    def dump(self):
        d = []
        d.append(struct.pack('!H', self.object_version))
        d.append(struct.pack('!H', self.length))
        d.append(struct.pack('!H', self.stream_number))
        d.append(struct.pack('!I', self.timestamp))
        d.append(struct.pack('B', self.reserved))
        d.append(struct.pack('B', self.flags))
        return ''.join(d)

    def __str__(self):
        return self.dump()

class RealChallenge(object):
    XOR_TABLE = [ 0x05, 0x18, 0x74, 0xd0, 0x0d, 0x09, 0x02, 0x53, 0xc0, 0x01,
                  0x05, 0x05, 0x67, 0x03, 0x19, 0x70, 0x08, 0x27, 0x66, 0x10,
                  0x10, 0x72, 0x08, 0x09, 0x63, 0x11, 0x03, 0x71, 0x08, 0x08,
                  0x70,	0x02, 0x10, 0x57, 0x05, 0x18, 0x54 ]
    def AV_WB32(d):
        """ Used by RealChallenge() """
        d = d.decode('hex')
        return list(struct.unpack('%sB' % len(d), d))
    def compute(rc1):
        """ Translated from MPlayer's source
        Computes the realchallenge response and checksum """
        buf = list()
        buf.extend( RealChallenge.AV_WB32('a1e9149d') )
        buf.extend( RealChallenge.AV_WB32('0e6b3b59') )
        
        rc1 = rc1.strip()
        
        if rc1:
            if len(rc1) == 40: rc1 = rc1[:32]
            if len(rc1) > 56: rc1 = rc1[:56]
            buf.extend( [ ord(i) for i in rc1 ] )
            buf.extend( [ 0 for i in range(0, 56 - len(rc1)) ] )
        
        # xor challenge bytewise with xor_table
        for i in range(0, len(RealChallenge.XOR_TABLE)):
            buf[8 + i] ^= RealChallenge.XOR_TABLE[i];
        
        sum = md5( ''.join([ chr(i) for i in buf ]) )
        
        response = sum.hexdigest() + '01d0a8e3'
        
        chksum = list()
        for i in range(0, 8):
            chksum.append(response[i * 4])
        chksum = ''.join(chksum)
        
        return (response, chksum)
    compute = staticmethod(compute)
    AV_WB32 = staticmethod(AV_WB32)

class RTSPClient(basic.LineReceiver):
    """ Provides RTSP protocol """

    __buffer = '' # Buffer from which lines are parsed
    attach_buffer = StringIO()
    length = None

    content_length = None # length of attached content
    content_type = None # type of attached content

    rtsp_length = None # RTSP Interleaved Binary Data length

    session = None # RTSP Session

    sent_options = False
    sent_setup = False
    sent_play = False
    sent_describe = False
    sent_parameter = False
    sent_bandwidth = False

    def sendCommand(self, command, path):
        """ Sends off an RTSP command
        These appear at the beginning of RTSP headers """
        self.sendLine('%s %s RTSP/1.0' % (command, path))

    def sendHeader(self, name, value):
        """ Sends off a header, same method as HTTP headers """
        self.sendLine('%s: %s' % (name, value))

    def sendHeaders(self, dict):
        if not dict:
            return
        for key, value in dict.items():
            self.sendHeader(key, value)

    def endHeaders(self):
        """ Sends \r\n which signifies the end of the headers """
        self.sendLine('')

    def sendMethod(self, method, target='*', headers=None):
        self.sendCommand(method, target)
        self.sendHeader('CSeq', self.cseq)
        self.cseq += 1
        self.sendHeaders(headers)
        self.endHeaders()

    def dataReceived(self, data):
        """Protocol.dataReceived.
        Translates bytes into lines, and calls lineReceived (or
        rawDataReceived, depending on mode.)
        """
        """ Checks for the $ flag signifying RTSP Interleaved data """
        self.__buffer = self.__buffer+data

        if self.paused:
            return

        while self.__buffer:
            # Checks for $ but only in place of the firstLine and only when
            # self.length is not set
            if not self.length and self.firstLine and len(
                self.__buffer) >= 4 and self.__buffer[0] == '$':
                header, self.__buffer = self.__buffer[:4], self.__buffer[4:]
                # Header should be:
                #    Magic $ (1 byte)
                #    Channel (1 byte)
                #    Length (2 bytes)
                self.rtsp_length = struct.unpack('!H', header[2:4])[0]
                self.length = self.rtsp_length
                if self.length == 0:
                    print('RTSP Interleaved length was 0!')
                self.attach_buffer = StringIO()
                self.setRawMode()
            if self.length:
                self.__buffer = self.rawDataReceived(self.__buffer)
                continue
            try:
                line, self.__buffer = self.__buffer.split(self.delimiter, 1)
            except ValueError:
                if len(self.__buffer) > self.MAX_LENGTH:
                    line, self.__buffer = self.__buffer, ''
                    return self.lineLengthExceeded(line)
                break
            else:
                linelength = len(line)
                if linelength > self.MAX_LENGTH:
                    exceeded = line + self.__buffer
                    self.__buffer = ''
                    return self.lineLengthExceeded(exceeded)
                why = self.lineReceived(line)
                if why or self.transport and self.transport.disconnecting:
                    return why
        else:
            data=self.__buffer
            self.__buffer=''
            if data:
                self.handleResponsePart(data)

    def lineReceived(self, line):
        """ Almost exactly the same as twisted.web.http.HTTPClient """
        if self.firstLine:
            self.headers = {}
            self.firstLine = 0
            l = line.split(None, 2)
            version = l[0]
            status = l[1]
            try:
                message = l[2]
            except IndexError:
                message = ''
            self.handleStatus(version, status, message)
            return
        if line:
            key, val = line.split(':', 1)
            val = val.lstrip()
            self.handleHeader(key, val)
            if key.lower() == 'content-length':
                self.content_length = int(val)
                self.length = self.content_length
        else:
            # End of the headers has been reached
            if self.content_length is not None:
                self._handleEndHeaders()
                self.setRawMode()
            else:
                self._handleEndHeaders()
            self.firstLine = 1

    def connectionMade(self):
        """ Connection is established
        Sends off the Options request """
        print('Connected!')
        self.headers = {}
        self.cseq = 1
        self.firstLine = 1

        self.sendNextMessage()

    # -----------------
    # Response Handlers
    # -----------------

    def handleStatus(self, version, status, message):
        """ Called when the status header is received """
        print(status)

    def handleHeader(self, key, value):
        """ Called when a single header is received
        Stores the header in dictionary self.headers
        Each dictionary value is a list and can hold multiple response values"""
        key = key.lower()

        # Store the session in self.session
        for k in ['session','etag']:
            if key == k:
                self.session = value
        # Grabs just the session, removes the timeout at the end
        if self.session:
            delim = self.session.find(';')
            if delim != -1:
                self.session = self.session[:delim]
        if key == 'content-type':
            self.content_type = value

        # Allow for multiple values per key
        l = self.headers[key] = self.headers.get(key, [])
        l.append(value)

    def sendNextMessage(self):
        """ Default method handles only the
        bare minimum Setup and Play messages
        Override this in base classes to change behavior """
        if not self.sent_setup:
            self.sent_setup = True
            self.sendSetup()
            self.endHeaders()
            return True
        if not self.sent_play:
            self.sent_play = True
            self.sendPlay()
            self.endHeaders()
            return True
        return False

    def _handleEndHeaders(self):
        """ Internal handleEndHeaders
        Checks the server's CSeq """
        if self.headers.get('cseq'):
            serverCSeq = int(self.headers['cseq'][0])
            if serverCSeq != self.cseq - 1:
                print('Server CSeq != Client CSeq: %s != %s' %
                      (serverCSeq, self.cseq - 1))
        self.handleEndHeaders()

    def handleEndHeaders(self):
        """ Called when all headers have been received """
        if self.content_length is not None:
            # We call sendNextMessage after the response has been received
            return
        self.sendNextMessage()

    def handleContentResponse(self, data, content_type=None):
        """ Called when the entire content-length has been received """

    def handleResponseEnd(self, data):
        """ Called when length of data has been received """
        if self.content_length:
            self.content_length = None
            self.handleContentResponse(data, self.content_type)
            print('resp end')
            self.sendNextMessage()
            self.content_type = None
        elif self.rtsp_length:
            self.rtsp_length = None
            self.handleInterleavedData(data)
        else:
            self.handleResponsePart(data)

    def handleInterleavedData(self, data):
        """ Called when an interleaved data frame is received """

    def handleResponsePart(self, data):
        """ Called when a chunk of raw data is received
        or when length of raw data has been received """

    def rawDataReceived(self, data):
        """ Called when data is received in raw data mode
        Gathers self.content-length worth of data
        Returns what it doesn't use """
        if self.length is not None:
            self.attach_buffer.write(data)
            buff_len = self.attach_buffer.tell()
            if buff_len >= self.length:
                data = self.attach_buffer.getvalue()
                data, rest = data[:self.length], data[self.length:]
                self.handleResponseEnd(data)
                self.length = None
                self.attach_buffer = StringIO()
                return rest

    # ----------------------
    # Packet Sending Methods
    # ----------------------

    def sendOptions(self, target='*', headers=None):
        """ Requests available OPTIONS from server """
        self.sendMethod('OPTIONS', target, headers)

    def sendDescribe(self, target='*', headers=None):
        """ Asks server to describe stream in sdp format """
        self.sendMethod('DESCRIBE', target, headers)

    def sendSetup(self, target='*', headers=None):
        """ Tells the server to setup the stream """
        self.sendMethod('SETUP', target, headers)

    def sendSetParameter(self, target='*', headers=None):
        """ Tells the server to set parameters for streaming """
        self.sendMethod('SET_PARAMETER', target, headers)

    def sendPlay(self, range='0-', target='*', headers={}):
        """ Tells the server to play the stream for you """
        headers['Range'] = 'npt=%s' % range
        self.sendMethod('PLAY', target, headers)


class RDTClient(RTSPClient):
    data_received = 0
    out_file = None
    prev_timestamp = None
    prev_stream_num = None
    streamids = []

    EOF = 0xff06
    LATENCY_REPORT = 0xff08

    # RDT Header:
    #   Packet Flags (1 byte)
    #   Sequence number / packet type (2 bytes)
    #      Packet Length (if specified in flags) (2 bytes)
    #   Flags2 (1 byte)
    #   Timestamp (4 bytes)
    #   Total reliable (2 bytes)
    #   Data --

    # packet_flags:
    #    0... .... = length included & 0x80: 0
    #    .1.. .... = need reliable & 0x40: 1
    #    ..00 000. = Stream ID: 0
    #    .... ...0 = Is reliable & 0x01: 0

    # Flags2:
    #    0... .... = Back-to-back & 0x80: 0
    #    .1.. .... = Slow data & 0x40: 1
    #    ..00 0011 = Asm Rule & 0x3F: 3

    def handleEndHeaders(self):
        if self.headers.get('realchallenge1'):
            self.realchallenge1 = self.headers['realchallenge1'][0]
        print('heh %s' % self.content_length)        
        if self.content_length is None:
            self.sendNextMessage()

    def handleContentResponse(self, data, content_type):
        """ Called when the entire content-length has been received
        Processes the SDP data """
        if content_type == 'application/sdp':
            self.subscribe = 'stream=0;rule=3,stream=0;rule=4,stream=1;rule=2,stream=1;rule=3'
            self.out_file = open(self.factory.filename, 'wb')
            self.streamids.append(1)

    def handleRDTData(self, data, rmff_ph):
        self.out_file.write(str(rmff_ph))
        self.out_file.write(data)

    def handleRDTPacket(self, data):
        """ Called with a full RDT data packet """
        header, data = data[:10], data[10:]
        packet_flags = struct.unpack('B', header[0])[0]

        packet_type = struct.unpack('!H', header[1:3])[0]
        if packet_type == self.EOF:
            if self.out_file:
                self.out_file.close()
            self.transport.loseConnection()
            self.factory.deferred.callback(0)
            return
        if packet_type == self.LATENCY_REPORT:
            return

        timestamp = struct.unpack('!I', header[4:8])[0]
        stream_num = (packet_flags >> 1) & 0x1f
        flags2 = struct.unpack('B', header[3])[0]

        # Creates the rmff_header_t which is
        # inserted between packets for output
        rmff_ph = rmff_pheader_t()
        rmff_ph.length = len(data) + 12 # + 12 for the size of rmff_ph
        rmff_ph.stream_number = stream_num
        rmff_ph.timestamp = timestamp
        if (flags2 & 0x01) == 0 and (self.prev_timestamp != timestamp or self.prev_stream_num != stream_num):
            # I believe this flag signifies a stream change
            self.prev_timestamp = timestamp
            self.prev_stream_num = stream_num
            rmff_ph.flags = 2
        else:
            rmff_ph.flags = 0

        self.handleRDTData(data, rmff_ph)

    def handleInterleavedData(self, data):
        """ Called when an interleaved data frame is received """
        self.data_received += len(data)
        self.factory.data_received = self.data_received

        # Each Interleaved packet can have multiple RDT packets
        while len(data) > 0:
            # Here we check packet_flags to see if the RDT header includes
            # the length of the RDT packet. If it does, we try to handle
            # multiple RDT packets.
            packet_flags = struct.unpack('B', data[0])[0]
            packet_type = struct.unpack('!H', data[1:3])[0]

            if packet_type == self.EOF:
                self.handleRDTPacket(data)
                return
            len_included = packet_flags & 0x80 == 0x80
            if len_included:
                packet_length = struct.unpack('!H', data[3:5])[0]
                packet, data = data[:packet_length], data[packet_length:]
                self.handleRDTPacket(packet)
            else:
                # If no length is given, assume remaining data is one packet
                self.handleRDTPacket(data)
                break

    def _sendOptions(self, headers={}):
        target = '%s://%s:%s' % (self.factory.scheme,
                                 self.factory.host,
                                 self.factory.port)
        headers['User-Agent'] = self.factory.agent
        headers['ClientChallenge'] = self.factory.CLIENT_CHALLENGE
        headers['PlayerStarttime'] = self.factory.PLAYER_START_TIME
        headers['CompanyID'] = self.factory.companyID
        headers['GUID'] = self.factory.GUID
        headers['RegionData'] = '0'
        headers['ClientID'] = self.factory.clientID
        headers['Pragma'] = 'initiate-session'
        self.sendOptions(target, headers)

    def _sendDescribe(self, headers={}):
        target = '%s://%s:%s%s' % (self.factory.scheme,
                                   self.factory.host,
                                   self.factory.port,
                                   self.factory.path)
        headers['Accept'] = 'application/sdp'
#        self.sendHeader('Bandwidth', '9999999999999999999') #10485800
        headers['GUID'] = self.factory.GUID
        headers['RegionData'] = '0'
        headers['ClientID'] = self.factory.clientID
        headers['SupportsMaximumASMBandwidth'] = '1'
        headers['Language'] = 'en-US'
        headers['Require'] = 'com.real.retain-entity-for-setup'
        if self.factory.username is not None:
            authstr = '%s:%s' % (self.factory.username,
                                 self.factory.password
                                 if self.factory.password else '')
            authstr = base64.b64encode(authstr)
            headers['Authorization'] = 'Basic %s' % authstr
        self.sendDescribe(target, headers)

    def _sendSetup(self, headers={}, streamid=0):
        target = '%s://%s:%s%s/streamid=%s' % (self.factory.scheme,
                                               self.factory.host,
                                               self.factory.port,
                                               self.factory.path,
                                               streamid)
        headers['If-Match'] = self.session
        headers['Transport'] = 'x-pn-tng/tcp;mode=play,rtp/avp/tcp;unicast;mode=play'
        self.sendSetup(target, headers)

    def _sendSetParameter(self, key, value, headers={}):
        target = '%s://%s:%s%s' % (self.factory.scheme, self.factory.host,
                                   self.factory.port, self.factory.path)
        headers['Session'] = self.session
        headers[key] = value
        self.sendSetParameter(target, headers)

    def _sendPlay(self, range='0-', headers={}):
        target = '%s://%s:%s%s' % (self.factory.scheme,
                                   self.factory.host,
                                   self.factory.port,
                                   self.factory.path)
        if self.session:
            headers['Session'] = self.session
        self.sendPlay(range, target, headers)

    def sendNextMessage(self):
        """ This method goes in order sending messages to the server:
        OPTIONS, DESCRIBE, SETUP, SET_PARAMETER, SET_PARAMETER, PLAY
        Returns True if it sent a packet, False if it didn't """
        print('nxt msg')
        if not self.sent_options:
            self.sent_options = True
            self._sendOptions()
            return True
        if not self.sent_describe:
            self.sent_describe = True
            self._sendDescribe()
            return True
        if not self.sent_setup:
            self.sent_setup = True
            print('setup')
            challenge_tuple = RealChallenge.compute(self.realchallenge1)
            headers = {'RealChallenge2': '%s, sd=%s' % challenge_tuple}
            self._sendSetup(headers)
            return True
        if self.streamids:
            print('setup')
            self._sendSetup(streamid=self.streamids.pop(0))
            return True
        if not self.sent_parameter:
            self.sent_parameter = True
            self._sendSetParameter('Subscribe', self.subscribe)
            return True
        if not self.sent_bandwidth:
            self.sent_bandwidth = True
            self._sendSetParameter('SetDeliveryBandwidth',
                                   'Bandwidth=99999999999;BackOff=0')
            return True
        if not self.sent_play:
            self.sent_play = True
            self._sendPlay()
            return True
        return False

class RTSPClientFactory(client.HTTPClientFactory):
    """ Holds the RTSP default headers """
    protocol = RTSPClient
    # The following 4 values are all related
    # Do not change them
    GUID = '00000000-0000-0000-0000-000000000000'
    CLIENT_CHALLENGE = '9e26d33f2984236010ef6253fb1887f7'
    PLAYER_START_TIME = '[28/03/2003:22:50:23 00:00]'
    companyID = 'KnKV4M4I/B2FjJ1TToLycw=='

    agent = 'RealMedia Player Version 6.0.9.1235 (linux-2.0-libc6-i386-gcc2.95)'
    clientID = 'Linux_2.4_6.0.9.1235_play32_RN01_EN_586'

    data_received = 0

    netloc = None

    def __init__(self, url, filename, timeout=0, agent=None):
        self.timeout = timeout
        if agent is None:
            agent = self.agent
        self.filename = filename

        self.setURL(url)
        self.waiting = 1
        self.deferred = defer.Deferred()

    def setURL(self, url):
        self.url = url
        parsed_url = urlsplit(url)
        self.scheme, self.netloc, self.path, self.query, self.fragment = parsed_url
        self.host = parsed_url.hostname
        if self.host is None:
            self.host = self.netloc

        self.username = parsed_url.username
        self.password = parsed_url.password

        self.port = parsed_url.port
        if self.port is None:
            self.port = 554


def success(result):
    print('Result: %s' % result)
    reactor.stop()

def error(failure):
    print('Failure!: %s' % failure.getErrorMessage())
    reactor.stop()

def progress(factory):
    print('Downloaded %s bytes' % factory.data_received)
    reactor.callLater(1, progress, factory)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-u', '', dest='url', help='url to download',
                      metavar='URL',
                      default='rtsp://212.58.252.3:554/radio4/1530_mon.ra')
    parser.add_option('-f', '', dest='file', help='file to save to',
                      metavar='FILENAME',
                      default='out.ra')
    options, args = parser.parse_args()
    options.url = 'rtsp://mtilatti:A20143335@216.47.135.110/secure/f08/ECON-423-1/10_08_08/ECON-423-1_10_08_08.rm'
    if options.url is None:
        print('You must enter a url to download\n')
        parser.print_help()
        exit()
    if not options.file or len(options.file) < 1:
        print('Invalid file name specified\n')
        parser.print_help()
        exit()

    log.startLogging(sys.stdout)
    factory = RTSPClientFactory(options.url, options.file)
    factory.protocol = RDTClient
    factory.deferred.addCallback(success).addErrback(error)
    reactor.connectTCP(factory.host, factory.port, factory)
    reactor.callLater(1, progress, factory)
    reactor.run()
