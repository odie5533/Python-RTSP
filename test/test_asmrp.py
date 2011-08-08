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
from asmrp import Asmrp

class test_asmrp(unittest.TestCase):
    def test_actual(self):
        rulestring = '#($Bandwidth < 41556),TimestampDelivery=T,DropByN=T,priority=9;#($Bandwidth >= 41556) && ($Bandwidth < 84000),AverageBandwidth=41556,Priority=9;#($Bandwidth >= 41556) && ($Bandwidth < 84000),AverageBandwidth=0,Priority=5,OnDepend=\"1\";#($Bandwidth >= 84000),AverageBandwidth=84000,Priority=9;#($Bandwidth >= 84000),AverageBandwidth=0,Priority=5,OnDepend=\"3\";'
        symbols = {'Bandwidth':85000}
        rulematches, symbols = Asmrp.asmrp_match(rulestring,symbols)
        self.assertEqual(rulematches, [3,4])
    def test_greaterthan_fail(self):
        rulestring = '#(5 > 50),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '0')
    def test_greaterthan(self):
        rulestring = '#(50 > 5),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
    def test_lessthan(self):
        rulestring = '#(10 < 1000),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
    def test_lessthan_fail(self):
        rulestring = '#(1000 < 10),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '0')
    def test_equal_fail(self):
        rulestring = '#(10 == 1000),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '0')
    def test_equal(self):
        rulestring = '#(10 == 10),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
    def test_equal_no_semicolon(self):
        rulestring = '#(10 == 10),result=1'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
    def test_equal_no_whitespace(self):
        rulestring = '#(10==10),result=1;'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
    def test_equal_lots_of_whitespace(self):
        rulestring = '#    (   10   ==   10   )   ,   result   =   1'
        symbols = {'result':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
    def test_equal_multiple_assignments(self):
        rulestring = '#(10 == 10),res=2,result=1;'
        symbols = {'result':'0','res':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
        self.assertEqual(symbols['res'], '2')
    def test_equal_multiple_assignments_whitespace(self):
        rulestring = '#  (  10  ==  10  )  ,  res  =  2  ,  result  =  1  ;'
        symbols = {'result':'0','res':'0'}
        rulematches, symbols = Asmrp.asmrp_match(rulestring, symbols)
        self.assertEqual(symbols['result'], '1')
        self.assertEqual(symbols['res'], '2')

if __name__ == '__main__':
    unittest.main()
