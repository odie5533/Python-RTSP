# Real Assembly Parser Tests
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

import unittest
from rdt import rn5_auth

## Example Traffic
'''
DESCRIBE rtsp://media.jku.at:8554/secure/lrs/2010W/DVD/DVD_LE_A04_K03.rm RTSP/1.0
CSeq: 2
Accept: application/sdp
User-Agent: RealMedia Player HelixDNAClient/10.0.0.15366 (linux-2.2-libc6-gcc32-i586)
Session: 568336094-1;timeout=80
Require: com.real.retain-entity-for-setup
Bandwidth: 1105836
Language: en-US
RegionData: 0
ClientID: Linux_3.8_10.0.0.15366_play32_RN01_EN_586
GUID: 00000000-0000-0000-0000-000000000000
SupportsMaximumASMBandwidth: 1

RTSP/1.0 401 Unauthorized
CSeq: 2
Date: Tue, 02 Apr 2013 12:09:37 GMT
Session: 568336094-1;timeout=80
Set-Cookie: cbid=gfiggmcldgifcldmeojorugqqojrktluekggkidlegffclplmsporpltmolnrtlpdfjghhil;path=/;expires=Thu,31-Dec-2037 23:59:59 GMT
WWW-Authenticate: RN5 realm="localhost.localdomain.ContentRealm", nonce="1364904577884338"

DESCRIBE rtsp://media.jku.at:8554/secure/lrs/2010W/DVD/DVD_LE_A04_K03.rm RTSP/1.0
CSeq: 3
Accept: application/sdp
User-Agent: RealMedia Player HelixDNAClient/10.0.0.15366 (linux-2.2-libc6-gcc32-i586)
Session: 568336094-1;timeout=80
Require: com.real.retain-entity-for-setup
Authorization: RN5 username="foooo", GUID="d4a9e9b1-9b8f-11e2-e75c-294704f7cbcb",realm="localhost.localdomain.ContentRealm",nonce="1364904577884338",response="7772fd6cef036c15362f76fe948156cc"
Bandwidth: 1105836
Language: en-US
RegionData: 0
ClientID: Linux_3.8_10.0.0.15366_play32_RN01_EN_586
GUID: 00000000-0000-0000-0000-000000000000
SupportsMaximumASMBandwidth: 1
'''


class test_asmrp(unittest.TestCase):
    def test_rn5(self):
        '''
        token from a wireshark capture with RealPlayer with the auth data
        foooo:baaaar
        '''
        result = rn5_auth(username='foooo', password='baaaar',
                          realm='localhost.localdomain.ContentRealm',
                          nonce='1364904577884338',
                          uuid='d4a9e9b1-9b8f-11e2-e75c-294704f7cbcb')
        self.assertEqual('7772fd6cef036c15362f76fe948156cc', result)


if __name__ == '__main__':
    unittest.main()
