#!/usr/bin/env python
import os
import os.path
import argparse
import random
import sys
sys.path.append("./")

""" Access Control Policy converter
    maintained by Truc Nguyen Lam, Univerisity of Southampton
"""
"""
Description:
    Remember the name

TODO:
    -

Changelog:
    2017.05.06  Initial version
"""


def saveFile(filename, string):
    try:
        outfile = open(filename, "w")
        outfile.write(string)
        outfile.close()
    except IOError:
        pass


def getRandomChoice():
    # return random.choice([True, False])
    return (not not random.getrandbits(1))


def getChoiceByPercent(percent):
    choices = [False] * (100 - percent) + [True] * percent
    return random.choice(choices)


def parsePolicy(inputfilename):
    if not os.path.isfile(inputfilename):
        print "Error: please provide correct input file"

    from antlr4 import FileStream, CommonTokenStream, ParseTreeWalker
    from hierarchygrammarLexer import hierarchygrammarLexer
    from hierarchygrammarParser import hierarchygrammarParser
    from myHierarchyListener import myHierarchyListener

    input = FileStream(inputfilename)
    lexer = hierarchygrammarLexer(input)
    stream = CommonTokenStream(lexer)
    parser = hierarchygrammarParser(stream)
    tree = parser.policy()
    listener = myHierarchyListener()
    walker = ParseTreeWalker()
    walker.walk(listener, tree)
    return listener.policy


def generatePolicy(args):
    # Parse policy first
    policy = parsePolicy(args.input)

    # Check output path
    if args.path:
        try:
            os.makedirs(args.path)
        except OSError:
            pass

    prefix = args.path + "/" + \
        os.path.basename(args.input) if args.path != "" else args.input

    # For roles, which means attribute here
    rolestr = "ATTRIBUTES\n"
    for r in policy.roles:
        rolestr += str(r) + "[1]\n"
    rolestr += ";\n\n"

    old_rolestr = "ROLES\n"
    for r in policy.roles:
        old_rolestr += str(r) + "\n"
    old_rolestr += ";\n\n"

    # For rules
    rulestr = "RULES\n"
    for ca_rule in policy.ca_rules:
        rulestr += ca_rule.toVACRuleWithHierarchy(policy.hier) + "\n"
    for cr_rule in policy.cr_rules:
        rulestr += cr_rule.toVACRuleWithHierarchy(policy.hier) + "\n"
    rulestr += ";\n\n"

    old_rulestr = "CA\n"
    for ca_rule in policy.ca_rules:
        old_rulestr += ca_rule.toVACRuleExplodeHierarchy(policy.hier) + "\n"
    old_rulestr += ";\n\nCR\n"
    for cr_rule in policy.cr_rules:
        old_rulestr += cr_rule.toVACRuleExplodeHierarchy(policy.hier) + "\n"
    old_rulestr += ";\n\n"

    for qindex, q in enumerate(policy.queries):
        # userlist = []
        userstr = "USERS\n"
        old_userstr = "USERS\n"
        initstr = "INIT\n"
        old_uastr = "UA\n"
        for i in range(0, args.nuser):
            # For user
            name = "user%s" % i
            userstr += name + "\n"
            old_userstr += name + "\n"
            # userlist.append(name)
            # For init
            initstr += "<" + name
            for r in policy.roles:
                if getChoiceByPercent(args.density):
                    initstr += ", " + str(r) + "=1"
                    old_uastr += "<" + name + ", " + str(r) + ">\n"
                else:
                    initstr += ", " + str(r) + "=0"
            initstr += '>\n'

        old_unlimituserstr = "NEWUSERS\n"
        for i in range(0, args.nnewuser):
            name = "new_user%s" % i
            userstr += name + "*\n"
            # userlist.append(name)
            # For init
            initstr += "<" + name
            tmplist = []
            for r in policy.roles:
                if getChoiceByPercent(args.density):
                    initstr += ", " + str(r) + "=1"
                    tmplist.append(str(r))
                else:
                    initstr += ", " + str(r) + "=0"
            initstr += '>\n'
            if len(tmplist) > 0:
                old_unlimituserstr += "<" + name + ", " + "& ".join(tmplist) + ">\n"
        old_unlimituserstr += ";\n\n"

        # For query
        for uindex, ua in enumerate(q.ua_configs):
            name = "quser%s" % uindex
            userstr += name + "\n"
            old_userstr += name + "\n"
            if len(ua) > 0:
                initstr += "<" + name
                for r in ua:
                    initstr += ", " + str(r) + "=1"
                    old_uastr += "<" + name + ", " + str(r) + ">\n"
                initstr += '>\n'

        querystr = "QUERY\n"
        old_querystr = "SPEC\n"
        querystr += "quser%s" % q.user_index
        old_querystr += "quser%s" % q.user_index
        for goalindex, r in enumerate(q.goal):
            newquerystr = querystr + ".%s=1;\n\n" % r
            old_newquerystr = old_querystr + " %s;\n\n" % r
            newuserstr = userstr + ";\n\n"
            old_newuserstr = old_userstr + ";\n\n"
            newinitstr = initstr + ";\n\n"
            old_newinitstr = old_uastr + ";\n\n"
            ret = newuserstr + rolestr + newinitstr + rulestr + newquerystr
            old_ret = old_newuserstr + old_unlimituserstr + old_rolestr + old_newinitstr + old_rulestr + old_newquerystr

            if args.format == "new":
                saveFile(prefix + "_%su_%snu_query%s_%s.txt" %
                         (args.nuser, args.nnewuser, qindex, goalindex), ret)
            elif args.format == "old":
                saveFile(prefix + "_%su_%snu_query%s_%s_arbac.txt" %
                         (args.nuser, args.nnewuser, qindex, goalindex), old_ret)
            else:
                saveFile(prefix + "_%su_%snu_query%s_%s.txt" %
                         (args.nuser, args.nnewuser, qindex, goalindex), ret)
                saveFile(prefix + "_%su_%snu_query%s_%s_arbac.txt" %
                         (args.nuser, args.nnewuser, qindex, goalindex), old_ret)


def main():
    parser = argparse.ArgumentParser(
        description='Access Control Policy Converter')
    parser.add_argument('-i', '--input', metavar='X',
                        help='input policy',
                        type=str, dest='input', required=True)
    parser.add_argument('-p', '--output', metavar='X',
                        help='output path',
                        type=str, dest='path', default="")
    parser.add_argument('-f', '--format', metavar='X',
                        help='output policy format {old, new, both}',
                        type=str, dest='format', default="both")
    parser.add_argument('-c', '--density', metavar='X',
                        help='density of user-role assignment (default: 20%%)',
                        type=int, dest='density', default=10)
    parser.add_argument('-n', '--users', metavar='X',
                        help='generate X normal users',
                        type=int, dest='nuser', default=2)
    parser.add_argument('-u', '--new-users', metavar='X',
                        help='generate X new users',
                        type=int, dest='nnewuser', default=0)
    args = parser.parse_args()
    generatePolicy(args)


if __name__ == '__main__':
    main()
