#!/usr/bin/python3
# coding: utf-8
#
# Layer 2 network neighbourhood discovery tool
# written by Benedikt Waldvogel (mail at bwaldvogel.de)

from __future__ import absolute_import, division, print_function
import os
import socket
import multiprocessing
import subprocess
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import math
import errno
import getopt
import sys
#Lista de endereços IP/nomes de host da rede local

print("\n")
print("__________________________ :              HUNTERHOST  PROJECT              : __________________________________")
print("\n")
print("__________________________ :           bY m0rg4n/b1n/b45h  2023            : __________________________________")

def pinger(job_q, results_q):
    """
    Do Ping
    :param job_q:
    :param results_q:
    :return:
    """
    DEVNULL = open(os.devnull, 'w')
    while True:

        ip = job_q.get()

        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip],
                                  stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass


def get_my_ip():
    """
    Find my IP address
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def map_network(pool_size=255):
    """
    Maps the network
    :param pool_size: amount of parallel ping processes
    :return: list of valid ip addresses
    """
    
    ip_list = list()
    
    # get my IP and compose a base like 192.168.1.xxx
    ip_parts = get_my_ip().split('.')
    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'
    
    # prepare the jobs queue
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()
    
    pool = [multiprocessing.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]
    
    for p in pool:
        p.start()
    
    # cue hte ping processes
    for i in range(1, 255):
        jobs.put(base_ip + '{0}'.format(i))
    
    for p in pool:
        jobs.put(None)
    
    for p in pool:
        p.join()
    
    # collect he results
    while not results.empty():
        ip = results.get()
        ip_list.append(ip)

    return ip_list


if __name__ == '__main__':

    print('Mapping...')
    lst = map_network()
    print(lst)

print("\n")
print("__________________________ :       Starting the host hunt, good luck       : __________________________________")
print("\n")
print("__________________________ :       <<<<<<<<  RUNNING|ARPING >>>>>>>>       : __________________________________")


logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warning("%s is too big. skipping" % net)
        return None

    return net


def scan_and_print_neighbors(net, interface, timeout=5):
    logger.info("arping %s on %s" % (net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.herror:
                # failed to resolve
                pass
            logger.info(line)
    except socket.error as e:
        if e.errno == errno.EPERM:     # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise


def main(interface_to_scan=None):
    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)

    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:

        if interface_to_scan and interface_to_scan != interface:
            continue

        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # skip docker interface
        if interface != interface_to_scan \
                and (interface.startswith('docker')
                     or interface.startswith('br-')
                     or interface.startswith('tun')):
            logger.warning("Skipping interface '%s'" % interface)
            continue

        net = to_CIDR_notation(network, netmask)

        if net:
            scan_and_print_neighbors(net, interface)


def usage():
    print("Usage: %s [-i <interface>]" % sys.argv[0])


if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:', ['help', 'interface='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(2)

    interface = None

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit()
        elif o in ('-i', '--interface'):
            interface = a
        else:
            assert False, 'unhandled option'

    main(interface_to_scan=interface)

