#!/usr/bin/env python3

from gevent import monkey
import sys
import cmx
from cmx import config

monkey.patch_all()

#only needed til impacket 0.9.8 ships !!
#sys.path.insert(0, str(config.THIRD_PARTY_PATH / 'impacket'))
