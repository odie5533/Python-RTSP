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
#
#
# Mostly taken from MPlayer's rmff.c

import struct

class rmff_fileheader_t:
    object_id = '.RMF'
    size = 18
    object_version = 0
    file_version = 0

    def getSize(self):
        return self.size

    def __init__(self, num_headers):
        self.num_headers = num_headers

    def dump(self):
        d = []
        d.append(self.object_id)
        d.append(struct.pack('!I', self.size))
        d.append(struct.pack('!H', self.object_version))
        d.append(struct.pack('!I', self.file_version))
        d.append(struct.pack('!I', self.num_headers))
        return ''.join(d)

    def __str__(self):
        return self.dump()

class rmff_prop_t:
    object_id = 'PROP'
    size = 50
    object_version = 0

    def getSize(self):
        return self.size

    def __init__(self, max_bit_rate, avg_bit_rate, max_packet_size,
                 avg_packet_size, num_packets, duration, preroll, index_offset,
                 data_offset, num_streams, flags):
        self.max_bit_rate = max_bit_rate
        self.avg_bit_rate = avg_bit_rate
        self.max_packet_size = max_packet_size
        self.avg_packet_size = avg_packet_size
        self.num_packets = num_packets
        self.duration = duration
        self.preroll = preroll
        self.index_offset = index_offset
        self.data_offset = data_offset
        self.num_streams = num_streams
        self.flags = flags

    def dump(self):
        d = []
        d.append(self.object_id)
        d.append(struct.pack('!I', self.size))
        d.append(struct.pack('!H', self.object_version))
        d.append(struct.pack('!I', self.max_bit_rate))
        d.append(struct.pack('!I', self.avg_bit_rate))
        d.append(struct.pack('!I', self.max_packet_size))
        d.append(struct.pack('!I', self.avg_packet_size))
        d.append(struct.pack('!I', self.num_packets))
        d.append(struct.pack('!I', self.duration))
        d.append(struct.pack('!I', self.preroll))
        d.append(struct.pack('!I', self.index_offset))
        d.append(struct.pack('!I', self.data_offset))
        d.append(struct.pack('!H', self.num_streams))
        d.append(struct.pack('!H', self.flags))
        return ''.join(d)

    def __str__(self):
        return self.dump()

class rmff_mdpr_t:
    object_id = 'MDPR'
    object_version = 0

    def __init__(self, stream_number, max_bit_rate, avg_bit_rate,
                 max_packet_size, avg_packet_size, start_time, preroll,
                 duration, stream_name, mime_type, type_specific_data):
        self.stream_number = stream_number
        self.max_bit_rate = max_bit_rate
        self.avg_bit_rate = avg_bit_rate
        self.max_packet_size = max_packet_size
        self.avg_packet_size = avg_packet_size
        self.start_time = start_time
        self.preroll = preroll
        self.duration = duration
        self.stream_name = stream_name
        self.mime_type = mime_type
        self.type_specific_data = type_specific_data

    def getSize(self):
        size = 46
        size += len(self.stream_name)
        size += len(self.mime_type)
        size += len(self.type_specific_data)
        return size        

    def dump(self):
        d = []
        d.append(self.object_id)
        d.append(struct.pack('!I', self.getSize()))
        d.append(struct.pack('!H', self.object_version))
        d.append(struct.pack('!H', self.stream_number))
        d.append(struct.pack('!I', self.max_bit_rate))
        d.append(struct.pack('!I', self.avg_bit_rate))
        d.append(struct.pack('!I', self.max_packet_size))
        d.append(struct.pack('!I', self.avg_packet_size))
        d.append(struct.pack('!I', self.start_time))
        d.append(struct.pack('!I', self.preroll))
        d.append(struct.pack('!I', self.duration))
        d.append(struct.pack('B', len(self.stream_name)))
        d.append(self.stream_name)
        d.append(struct.pack('B', len(self.mime_type)))
        d.append(self.mime_type)
        d.append(struct.pack('!I', len(self.type_specific_data)))
        d.append(self.type_specific_data)
        return ''.join(d)

    def __str__(self):
        return self.dump()
        

class rmff_cont_t:
    object_id = 'CONT'
    object_version = 0

    def __init__(self, title, author, copyright, comment):
        self.title = title
        self.author = author
        self.copyright = copyright
        self.comment = comment

    def getSize(self):
        return len(self.title) + len(self.author) + len(self.copyright) + len(self.comment) + 18

    def dump(self):
        d = []
        d.append(self.object_id)
        d.append(struct.pack('!I', self.getSize()))
        d.append(struct.pack('!H', self.object_version))
        for field in [self.title, self.author, self.copyright, self.comment]:
            d.append(struct.pack('!H', len(field)))
            d.append(field)
        return ''.join(d)

    def __str__(self):
        return self.dump()

class rmff_data_t:
    object_id = 'DATA'
    size = 18
    object_version = 0

    def getSize(self):
        return self.size

    def __init__(self, num_packets, next_data_header):
        self.num_packets = num_packets
        self.next_data_header = next_data_header

    def dump(self):
        d = []
        d.append(self.object_id)
        d.append(struct.pack('!I', self.size))
        d.append(struct.pack('!H', self.object_version))
        d.append(struct.pack('!I', self.num_packets))
        d.append(struct.pack('!I', self.next_data_header))
        return ''.join(d)

    def __str__(self):
        return self.dump()

class rmff_header_t:
    def __init__(self):
        self.fileheader = None
        self.prop = None
        self.streams = []
        self.cont = None
        self.data = None

    def dump(self):
        # Recomputes the data offset
        self.prop.data_offset = self.fileheader.getSize() + self.prop.getSize() + self.cont.getSize() + sum(s.getSize() for s in self.streams)
        d = []
        d.append(self.fileheader.dump())
        d.append(self.prop.dump())
        d.append(self.cont.dump())
        for s in self.streams:
            d.append(s.dump())
        d.append(self.data.dump())
        return ''.join(d)

class rmff_pheader_t:
    """ The contents of this class get inserted
    between RDT data in the output file """
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
