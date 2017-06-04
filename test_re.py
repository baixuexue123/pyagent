#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re


print re.findall(r'(\w+)', 'jquery-1.12.3-(abc)-(123).zip')

print re.findall(r'(?:\()\w+(?:\))', 'jquery-1.12.3-(abc)-(123).zip')

print re.findall(r'(?<=\()\w+(?=\))', 'jquery-1.12.3-(abc)-(123).zip')


print re.findall('industr(?:y|ies)', 'industry-industry')

# 正向肯定界定
print re.findall("Windows(?=95|98|NT|2000)", 'Windows2000')
print re.findall("Windows(?=95|98|NT|2000)", 'Windows3.1')

# 正向否定界定
print re.findall("Windows(?!95|98|NT|2000)", 'Windows2000')
print re.findall("Windows(?!95|98|NT|2000)", 'Windows3.1')

# 反向肯定界定
print re.findall("(?<=95|98|NT)Windows", '98Windows')
print re.findall("(?<=95|98|NT)Windows", '3.1Windows')

# 反向否定界定
print re.findall("(?<!95|98|NT)Windows", '98Windows')
print re.findall("(?<!95|98|NT)Windows", '3.1Windows')


# 在python和Perl中两个反向界定的表达式exp只允许使用定长文本
# 否则报错error: look-behind requires fixed-width pattern
try:
    re.compile("(?<!95|98|NT|2000)Windows")
except re.error as e:
    print e


print re.findall(r'(?<=\()\S+?(?=\))', 'jquery-1.12.3-(abc中文123)-(efg中文456).zip')

print re.findall('(?::((?:\\\\.|[^\\\\>]+)+)?)?', ':\\')
