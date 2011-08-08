# Real Assembly Parser
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
# Logging can be enabled in the init method

import logging

class RuleString:
    """ Buffer containing the ASM rule book """
    def __init__(self, string):
        self._str = string
        self.idx = 0
        
    def seek_end(self):
        self.idx = len(self._str)-1

    def eof(self):
        return self.idx >= len(self._str)-1

    def __getitem__(self, key):
        return self._str[self.idx + key]

    def next(self):
        self.idx += 1
        self.sym = self._str[self.idx]
        return self.sym

    def nextChar(self):
        self.next()
        while len(self.sym.strip()) == 0:
            self.next()
        return self.sym

    def isCharElseNext(self):
        if self.sym.strip():
            return self.sym
        else:
            return self.nextChar()

    def dump(self, amount):
        return self._str[self.idx:self.idx + amount]
        

class Asmrp:
    eval_chars = ['<','=','>']
    special_chars = ['$','#',')','(']

    def __init__(self, rules, symbols):
        logger = logging.getLogger('ASMRP')
# Uncomment the following to enable logging
#        logging.basicConfig(level=logging.DEBUG, filename='asmrp.txt')
        
        self.logger = logger
        
        self.rules = rules
        self.logger.debug('Rules: ' + rules)
        self.matches = []
        self.symbols = symbols
        self.special_chars.extend(self.eval_chars)
        self.indent = ''

    def asmrp_find_id(self, rules):
        symbol = ''
        while rules.sym not in self.special_chars:
            symbol += rules.sym
            rules.next()
        symbol = symbol.strip()
        self.logger.debug(self.indent + 'Found symbol: %s => %s' % (symbol, self.symbols[symbol]))
        return self.symbols[symbol]

    def asmrp_operand(self, rules):
        rules.isCharElseNext()
        self.logger.debug(self.indent + 'Finding operand: %s' % rules.sym)
        if rules.sym == '$':
            self.logger.debug(self.indent + 'Found variable symbol')
            rules.next()
            return self.asmrp_find_id(rules)
        elif rules.sym.isdigit():
            self.logger.debug(self.indent + 'Found numerical operand')
            number = ''
            while rules.sym.isdigit():
                number += rules.sym
                rules.next()
            self.logger.debug(self.indent + 'Number: %s' % number)
            return int(number)
        elif rules.sym == '(':
            self.logger.debug(self.indent + 'Open paren')
            rules.nextChar()
            self.indent += ' '
            ret = self.asmrp_condition(rules)
            rules.isCharElseNext()
            self.indent = self.indent[:-1]
            if rules.sym != ')':
                self.logger.debug(self.indent + 'Expected right paren!')
            else:
                self.logger.debug(self.indent + 'Close paren')
            rules.nextChar()
            return ret
        else:
            self.logger.debug('Unknown operand!')
            exit()

    def asmrp_comp_expression(self, rules):
        """ Evaluates an expression such as $Bandwidth > 500 """
        self.logger.debug(self.indent + 'Expression getting a operand')
        self.indent += ' '
        a = self.asmrp_operand(rules)
        self.indent = self.indent[:-1]
        rules.isCharElseNext()
        if rules.sym in [',',';',')','&','|']:
            return a
        operator = rules.sym
        rules.next()
        if rules.sym == '=':
            operator += '='
            rules.nextChar()
        self.logger.debug(self.indent + 'Expression operator: %s' % operator)
        self.logger.debug(self.indent + 'Expression getting b operand')
        self.indent += ' '
        b = self.asmrp_operand(rules)
        self.indent = self.indent[:-1]
        self.logger.debug(self.indent + 'Expression: %s %s %s' % (a,operator,b))
        if operator == '<':
            return a < b
        if operator == '<=':
            return a <= b
        if operator == '==':
            return a == b
        if operator == '>':
            return a > b
        if operator == '>=':
            return a >= b

    def asmrp_condition(self, rules):
        """ Evaluates a condition
        e.g. $Bandwidth > 500 && $Bandwidth < 1000 """
        self.logger.debug(self.indent + 'Condition getting a operand')
        self.indent += ' '
        a = self.asmrp_comp_expression(rules)
        self.indent = self.indent[:-1]
        self.logger.debug(self.indent + 'Condition a: %s' % a)
        while rules.dump(2) in ['&&','||']:
            operator = rules.dump(2)
            self.logger.debug(self.indent + 'Condition Operator: %s' % operator)
            rules.nextChar()
            rules.nextChar()
            b = self.asmrp_comp_expression(rules)
            self.logger.debug(self.indent + 'Condition: %s %s %s' % (a,operator,b))
            if operator == '&&':
                return a and b
            if operator == '||':
                return a or b
        self.logger.debug(self.indent + 'Returning condition: %s' % a)
        return a

    def asmrp_assignment(self, rules):
        self.logger.debug(self.indent + 'Performing assignment')
        name = ''
        while rules.sym != '=':
            name += rules.sym
            rules.next()
        name = name.strip()
        self.logger.debug(self.indent + 'Assignment name: %s' % name)
        rules.nextChar()
        value = rules[0]
        while rules[0] not in [',',';'] and not rules.eof():
            rules.next()
            value += rules.sym
        while ord(value[-1]) < 33 or value[-1] in [',',';']:
            value = value[:-1]
        self.symbols[name] = value
        self.logger.debug(self.indent + 'Assignment [%s] = %s' % (name,value))

    def asmrp_rule(self, rules):
        oper = rules[0]
        self.logger.debug('Next oper: %s' % oper)
        if oper == '#':
            self.logger.debug('# Assignment')
            # Assignment
            rules.nextChar()
            self.indent += ' '
            ret = self.asmrp_condition(rules)
            self.logger.debug('Assignment condition result: %s' % ret)
            if ret:
                while rules[0] == ',' and not rules.eof():
                    rules.nextChar()
                    self.asmrp_assignment(rules)
                if not rules.eof():
                    rules.nextChar()
                return True
            else:
                while rules[0] != ';' and not rules.eof():
                    rules.nextChar()
                if not rules.eof():
                    rules.nextChar()
        else:
            self.logger.debug('Unknown operator: %s' % oper)
            rules.seek_end()
            return False

    def asmrp_eval(self, rules):
        rules = RuleString(rules)
        rule_num = 0
        num_matches = 0
        while not rules.eof():
            if self.asmrp_rule(rules):
                self.matches.append(rule_num)
                num_matches += 1
            rule_num += 1
        return self.matches

    @staticmethod
    def asmrp_match(rules, symbols):
        asmrp = Asmrp(rules, symbols)
        return asmrp.asmrp_eval(rules), asmrp.symbols
