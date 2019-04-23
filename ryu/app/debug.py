#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from ryu.cmd import manager


def main():
    #用要调试的脚本的完整路径取代/home/tao/workspace/python/ryu_test/app/simple_switch_lacp_13.py就可以了
    sys.argv.append('/home/young/Desktop/ryu/ryu/app/simple_netstream.py')
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()

if __name__ == '__main__':
    main()
