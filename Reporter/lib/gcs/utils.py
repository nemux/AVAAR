#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
package.module
~~~~~~~~~~~~~

A description which can be long and explain the complete
functionality of this module even with indented code examples.
Class/Function however should not be documented here.

:copyright: 2014 by NeMuX, see AUTHORS for more details
:license: Apache 2.0, see LICENSE for more details
"""

__author__ = "NeMuX"
__copyright__ = "Copyright 2014"
__credits__ = ["NeMuX"]
__license__ = "Apache 2.0"
__version__ = "0.1"
__maintainer__ = "NeMuX"
__email__ = "jaraujo@globalcybersec.com"
__status__ = "Development"


def unicode_string(string):
    return unicode(string,'utf8')

def enum(*args):
     enums = dict(zip(args, range(len(args))))
     return type('Enum', (), enums)