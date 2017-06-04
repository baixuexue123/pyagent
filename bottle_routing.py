#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

import bottle

router = bottle.Router()


# router.add('/static', 'GET', '/static')
# env = {'PATH_INFO': '/static', 'REQUEST_METHOD': 'GET'}

# def test(request): pass

# router.add('/:test', 'GET', test)
# env = {'PATH_INFO': '/test', 'REQUEST_METHOD': 'GET'}
#
# target, urlargs = router.match(env)
#
# print target
# print urlargs


old_rule_syntax = re.compile('(\\\\*)(?:(?::([a-zA-Z_][a-zA-Z_0-9]*)?()(?:#(.*?)#)?)|(?:<([a-zA-Z_][a-zA-Z_0-9]*)?(?::([a-zA-Z_]*)(?::((?:\\\\.|[^\\\\>]+)+)?)?)?>))')

rule_syntax = re.compile('(\\\\*)(?:<([a-zA-Z_][a-zA-Z_0-9]*)?(?::([a-zA-Z_]*)(?::((?:\\\\.|[^\\\\>]+)+)?)?)?>)')

# print '----------------------------------------'
#
# for match in rule_syntax.finditer('/action/item'):
#     print match.groups()

# print '----------------------------------------'
#
# offset, prefix = 0, ''
# rule = '/<action>/<item>'
# for match in rule_syntax.finditer(rule):
#     prefix += rule[offset:match.start()]
#     g = match.groups()
#     print g
#     print prefix
#
# print
#
# for i in router._itertokens('/<action>/<item>'):
#     print i

# print '----------------------------------------'
#
# for match in rule_syntax.finditer('/<action>/<item>'):
#     print match.groups()
#
# print '----------------------------------------'
#
# for match in rule_syntax.finditer('/web/\\<its>/<:re:.+>/<test>/<name:re:[a-z]+>/'):
#     print match.groups()

# print '----------------------------------------'
#
# for match in rule_syntax.finditer('/<:re:anon>/match'):
#     print match.groups()

# print '----------------------------------------'
#
# for match in rule_syntax.finditer('/int/<i:test>'):
#     print match.groups()
#
# print '----------------------------------------'
#
# for match in rule_syntax.finditer('/object/<id:float>'):
#     print match.groups()


pattern1 = re.compile('(?:<([a-zA-Z_][a-zA-Z_0-9]*)?>)')

pattern = re.compile('(?:<([a-zA-Z_][a-zA-Z_0-9]*)?(?::([a-zA-Z_]*)(?::((?:\\\\.|[^\\\\>]+)+)?)?)?>)')

print '----------------------------------------'

for match in pattern.finditer('/object/view'):
    print match.groups()

print

for i in router._itertokens('/object/view'):
    print i

print '----------------------------------------'

for match in pattern.finditer('/object/<action>/<item>'):
    print match.groups()

print

for i in router._itertokens('/object/<action>/<item>'):
    print i

print '----------------------------------------'

for match in pattern.finditer('/object/<id:int>'):
    print match.groups()

print

for i in router._itertokens('/object/<id:int>'):
    print i

print '----------------------------------------'

for match in pattern.finditer('/<its>/<:re:.+>/<test>/<name:re:[a-z]+>/'):
    print match.groups()

print

for i in router._itertokens('/<its>/<:re:.+>/<test>/<name:re:[a-z]+>/'):
    print i
