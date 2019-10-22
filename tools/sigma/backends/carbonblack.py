# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Roey

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
# from netaddr import *
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin
from sigma.parser.modifiers.base import SigmaTypeModifier

from .. eventdict import event

class SplunkBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Splunk Search Processing Language (SPL)."""
    identifier = "carbonblack"
    active = True
    index_field = "index"

    # \   -> \\
    # \*  -> \*
    # \\* -> \\*
    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " and "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "%s"
    listExpression = "%s"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s:%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, key, value):
        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return "(" + (" OR ".join(['%s=%s' % (key, self.generateValueNode(item)) for item in value])) + ")"

    def generateMapItemNode(self, node):
        fieldname, value = node
        value = self.cleanValue(value)
        if(fieldname == "EventID" and value in event):
            fieldname = event[value][0]
            value = event[value][1]
        transformed_fieldname = self.fieldNameMapping(fieldname, value)
        if(transformed_fieldname == "ipaddr"):
            value = self.cleanIPRange(value)
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            return self.mapExpression % (transformed_fieldname, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(transformed_fieldname, value)
        elif isinstance(value, SigmaTypeModifier):
            return self.generateMapItemTypedNode(transformed_fieldname, value)
        elif value is None:
            return self.nullExpression % (transformed_fieldname, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))


    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val | search val %s %s" % (agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.cond_op, agg.condition)
        else:
            if agg.aggfunc_notrans == 'count':
                if agg.aggfield == None :
                    return " | eventstats count as val by %s| search val %s %s" % (agg.groupfield, agg.cond_op, agg.condition)
                else:
                    agg.aggfunc_notrans = 'dc'
            return " | eventstats %s(%s) as val by %s | search val %s %s" % (agg.aggfunc_notrans, agg.aggfield or "", agg.groupfield or "", agg.cond_op, agg.condition)

    def cleanValue(self, value):
        new_value = value
        if type(value) is str:
            while re.search(r'\\[\/\\\"]',str(new_value)):
                new_value = re.sub(r'\\\\', r'\\' , new_value)
                new_value = re.sub(r'\\\/', r'\/' , new_value)
                new_value = re.sub(r'\\\"', r'\"' , new_value)
                new_value = re.sub(r"\\\'", r"\'" , new_value)
            print (new_value)
        if type(value) is list:
            for vl in value:
                vl = self.cleanValue(vl)
        return new_value

    def cleanIPRange(self,value):
        new_value = value
        if type(value) is str and value.find('*') :
            sub =  value.count('.')
            if(value[-2:] == '.*'):
                value = value[:-2]
            min_ip = value + '.0' * (4 - sub)
            max_ip = value + '.255' * (4 - sub)
            new_value = '['+ min_ip + ' TO ' + max_ip + ']'
            # ip = IPNetwork(value + '/' + str(sub))
            # min_ip = str(ip[0])
            # max_ip = str(ip[-1])
        if type(value) is list:
            for vl in value:
                vl = self.cleanIPRange(vl)
        return new_value

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        columns = list()

        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after
            # if mapped is not None:
            #     result += fields

            return result
    
