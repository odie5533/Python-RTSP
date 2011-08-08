# Pythonic SDP/SDPPLIN Parser
# SDP = Session Description Protocol
#
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

import base64

def _parse_sdpplin_line(item):
    """ Returns a (name,value) tuple when given an Sdpplin attribute
    e.g. AvgPacketSize:integer;744 => (AvgPacketSize,744)
    """
    name = item.split(':')[0]
    value = item[len(name)+ 1:]
    if value.find(';') != -1:
        #type = value.split(';')[0]
        #value = value[len(type) + 1:]
	type, sep, value = value.partition(';')
        if type == 'integer':
            value = int(value)
        if type == 'buffer':
            value = base64.b64decode(value[1:-1])
        if type == 'string':
            value = value[1:-1]
    return name, value

class SDPMediaDesc:
    """ Holds the (a)ttribute and (b)andwidth values for an SDP Media Desc """
    def __init__(self):
        self.a = []
        self.b = []

class SDPParser:
    def __init__(self, data = None):
        """ Parses a full SDP data string.
        Alternatively, send lines to the parseLine method. """
        self.v = []
        self.o = []
        self.s = []
        self.i = []
        self.t = []
        self.a = []
        self.media_descriptions = []

        self.last_desc = None

        # Variables are provided for convenience
        self.protocol_version = None
        self.session_name = None
        self.session_desc = None
        self.start_time = None
        self.stop_time = None


        if data is None:
            return
        lines = [ l for l in data.split('\r\n') if l ]
        for line in lines:
            self.parseLine(line)

    def saveSDP(self, filename):
        """ Not finished """
        f = open(filename, 'w')
        for type in [ 'v', 'o', 's', 'i', 't', 'a' ]:
            for val in getattr(self, type):
                f.write('%s=%s\r\n' % (type, val))
        for mdesc in self.media_descriptions:
            for type in [ 'a', 'b' ]:
                for val in getattr(mdesc, type):
                    f.write('%s=%s\r\n' % (type, val))
        f.write('\r\n')
        f.close()

    def parseLine(self, line):
        """ Parses an SDP line. SDP protocol requires lines be parsed in order
        as the m= attribute tells the parser that the following a= values
        describe the last m= """
        type = line[0]
        value = line[2:].strip()
        if type == 'v':
            self.v.append(value)
            self.protocol_version = value
        elif type == 'o':
            self.o.append(value)
        elif type == 's': # Session Name
            self.s.append(value)
            self.session_name = value
        elif type == 'i': # Session Description
            self.i.append(value)
            self.session_desc = value
        elif type =='t': # Time
            try:
                start_time, stop_time = [`t` for t in value.split(' ')]
            except ValueError:
                pass
        elif type == 'a':
            if self.last_desc is None:
                # Appends to the session attributes
                self.a.append(value)
            else:
                # or to the media description attributes
                self.last_desc.a.append(value)
        elif type == 'm':
            self.last_desc = SDPMediaDesc()
            self.media_descriptions.append(self.last_desc)
        elif type == 'b':
            self.last_desc.b.append(value)
        else:
            # Need to add email and phone
            raise TypeError('Unknown type: %s' % type)

class SdpplinMediaDesc(SDPMediaDesc):
    """ Extends the SDPMediaDesc by providing dictionary-style access to
    the sdpplin variables.
    e.g. instead of media_desc.a[7] returning "MaxBitRate:integer;64083"
         media_desc["MaxBitRate"] returns an integer 64083
    """
    def __iter__(self):
        for key in self.attributes:
            yield key

    def items(self):
        return [(key,self.attributes[key]) for key in self.attributes]

    def __getitem__(self, name):
        return self.attributes[name]

    def __init__(self, media_desc):
        self.a = media_desc.a
        self.b = media_desc.b

        self.attributes = {}
        self.duration = None

        for item in media_desc.a:
            name, value = _parse_sdpplin_line(item)
            if name == 'control':
                self.attributes[value.split('=')[0]] = int(value.split('=')[1])
            if name == 'length':
                self.duration = int(float(value.split('=')[1]) * 1000)
            self.attributes[name] = value

class Sdpplin(SDPParser):
    """ Extends the SDPParser by providing dictionary-style access to
    the sdpplin variables.
    e.g. instead of sdp.a[1] returning "StreamCount:integer;2"
         sdp["StreamCount"] returns 2
    """
    def __init__(self, data):
        self.attributes = {}
        self.streams = []

        sdp = SDPParser(data)

        # Adds attributes to self
        for item in sdp.a:
            name, value = _parse_sdpplin_line(item)
            if name in ['Title', 'Author', 'Copyright']:
                value = value.strip(chr(0))
            self.attributes[name] = value

        # Adds SdpplinMediaDesc to streams[] for each SDPMediaDesc
        for media_desc in sdp.media_descriptions:
            sdpplin_media_desc = SdpplinMediaDesc(media_desc)
            self.streams.append(sdpplin_media_desc)

    def __iter__(self):
        for key in self.attributes:
            yield key

    def items(self):
        return [(key,self.attributes[key]) for key in self.attributes]

    def __getitem__(self, name):
        return self.attributes[name]
