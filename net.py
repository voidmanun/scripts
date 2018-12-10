#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ****************************************************************#
# Create Date: 2017-02-22 12:06
# Modify Date: 2017-02-22 12:06
# Function:
# ***************************************************************#
import socket
import sys
import time
import struct
import logging
import argparse


def init_log():
    '''
    初始化logging模块
    '''
    # 创建一个logger;
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # 创建一个handler,用于写入日志文件;
    fh = logging.FileHandler('/tmp/conncheck.log')
    fh.setLevel(logging.INFO)
    # 定义handler的输出格式
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    # 给logger添加handler
    logger.addHandler(fh)


def check_conn(sip, dip, dport, sport=0):
    '''指定源端口，目的端口进行探测，通过rst断开连接'''
    l_onoff = 1
    l_linger = 0
    try:
        s = socket.socket()
        s.settimeout(1)
        s.bind((sip, sport))
        real_port = s.getsockname()[1]
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack('ii', l_onoff, l_linger))
        errno = s.connect_ex((dip, dport))
        s.close()
        return errno, real_port
    except socket.error as e:  # 源目地址，端口绑定失败，导致连接无法建立
        s.close()
        logging.error(e)
        return e.errno, real_port
    except Exception, e:
        s.close()
        logging.error(e)
        return e.errno, real_port


def test_conn(sip, dip, dport, sports):
    '''进行端口连通性探测，针对不同的返回码，确认不同的问题:
        11: 目的地址不可达;
        98: 地址/端口已经被占用;
        0: 连接成功;
    '''
    logging.info('Start to check now !')
    while True:
        sleeptime = 0
        for sport in sports:
            errno, real_port = check_conn(sip, dip, dport, sport)
            if errno == 11:
                logging.error('test %s:%s from sport %s failed, errno: %s' %
                              (dip, dport, real_port, errno))
            elif errno == 98:
                logging.warning('Port/ip_addr has been used already')
                time.sleep(2)
                sleeptime += 1
            elif errno == 0:
                logging.info('test %s:%s from sport %s success' %
                             (dip, dport, real_port))
                time.sleep(2)
                sleeptime += 2
            else:
                logging.error('socket errno: %s' % errno)
        logging.info('last cycle takes %ss.' % sleeptime)


def get_options(x):
    parser = argparse.ArgumentParser(epilog=usage,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbosity", action="count",
                        help="increase output verbosity")
    parser.add_argument("-s", "--src_ip",
                        help="specify the src_ip")
    parser.add_argument("-d", "--dst_ip",
                        help="specify the dst_ip")
    parser.add_argument("-i", "--src_port",
                        help="specify the src_port")
    parser.add_argument("-p", "--dst_port",
                        help="specify the dst_port")
    opt = parser.parse_args(args=x)
    if opt.verbosity > 2:
        sys.stderr.write("%s\n" % opt)
    return opt


def main():
    '''获取ip，port等信息'''
    opt = get_options(sys.argv[1:])
    if opt.src_ip:
        src_ip = opt.src_ip
    else:
        src_ip = ''
    if opt.dst_ip:
        dst_ip = opt.dst_ip
    else:
        raise Exception('Please specify the dst_ip')
    if opt.dst_port:
        dport = int(opt.dst_port)
    else:
        raise Exception('Please specify the dst_port')
    if opt.src_port:
        sport = [int(port) for port in opt.src_port.split(',')]
    else:
        sport = [0]
    test_conn(src_ip, dst_ip, dport, sport)


usage = """

Usage:
    ./check_conn.py -s [ src_ip ] -d [ dst_ip ] -i [ src_port ] -p [ dst_port ]
examples:
    check_conn.py -s 192.168.1.27 -d 192.168.1.25 -i 34567 -p 80
指定多个源port:
    check_conn.py -s 192.168.1.27 -d 192.168.1.25 -i 34567,34555 -p 80
不指定源port，源地址, 将随机绑定源端口，绑定默认网卡:
    check_conn.py -d 192.168.1.25 -p 80
"""

if __name__ == '__main__':
    init_log()
    main()
