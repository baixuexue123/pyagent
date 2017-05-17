#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division

import os
import platform
import time
import datetime
import socket
import fcntl
import struct
import re
import json
import shutil
import urllib
import urllib2
import zipfile
import hashlib
import logging
import argparse
import subprocess
import threading
import multiprocessing

from Queue import Queue, Empty, PriorityQueue
from array import array
from SocketServer import ThreadingMixIn
from SimpleXMLRPCServer import SimpleXMLRPCServer

import psutil
import netifaces

__version__ = '0.0.1'

# **********************************************************************************
# 获取机器的静态信息
# **********************************************************************************


def dmidecode_system(pattern=re.compile(r'System Information\n\tManufacturer: (?P<manufacturer>.*)\n'
                                        r'\tProduct Name: (?P<product_name>.*)\n'
                                        r'\tVersion: (?P<version>.*)\n'
                                        r'\tSerial Number: (?P<serial_number>.*)\n'
                                        r'\tUUID: (?P<uuid>.*)\n'
                                        r'\t(.)*\n'
                                        r'\t(.)*\n'
                                        r'\tFamily: (?P<family>.*)\n')):

    content = subprocess.check_output(['sudo', 'dmidecode'])
    match = re.search(pattern, content)
    return {
        'manufacturer': match.group('manufacturer'),
        'product-name': match.group('product_name'),
        'version': match.group('version'),
        'serial-number': match.group('serial_number'),
        'uuid': match.group('uuid'),
        'family:': match.group('family'),
    }


def _linux_os_release():
    """Try to determine the name of a Linux distribution.
    This function checks for the /etc/os-release file.
    It takes the name from the 'NAME' field and the version from 'VERSION_ID'.
    An empty string is returned if the above values cannot be determined.
    """
    pretty_name = ''
    ashtray = {}
    keys = ['NAME', 'VERSION_ID']
    try:
        with open(os.path.join('/etc', 'os-release')) as f:
            for line in f:
                for key in keys:
                    if line.startswith(key):
                        ashtray[key] = line.strip().split('=')[1][1:-1]
    except (OSError, IOError):
        return pretty_name

    if ashtray:
        if 'NAME' in ashtray:
            pretty_name = ashtray['NAME']
        if 'VERSION_ID' in ashtray:
            pretty_name += ' {}'.format(ashtray['VERSION_ID'])

    return pretty_name


def cpu_info(vendor_pattern=re.compile(r'vendor_id([ \t])+: (?P<vendor_id>.*)\n'),
             model_pattern=re.compile(r'model name([ \t])+: (?P<model_name>.*)\n'),
             processor_pattern=re.compile(r'(processor[ \t]+: \d+\n)')):

    with open('/proc/cpuinfo') as f:
        content = f.read()
        try:
            num = os.sysconf("SC_NPROCESSORS_ONLN")
        except ValueError:
            # as a second fallback we try to parse /proc/cpuinfo
            num = len(re.findall(processor_pattern, content))
        return {
            'vendor': re.search(vendor_pattern, content).group('vendor_id').strip(),
            'model': re.search(model_pattern, content).group('model_name').strip(),
            'core_num': num,
        }


def netcard_info():

    def _get_hwaddr(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    ifaces = netifaces.interfaces()
    if 'lo' in ifaces:
        ifaces.remove('lo')
    ret = {}
    for i in ifaces:
        try:
            netcard = netifaces.ifaddresses(i)[netifaces.AF_INET][0]
        except KeyError:
            continue

        ret[i] = {
            'mac': _get_hwaddr(i),
            'broadcast': netcard['broadcast'],
            'mask': netcard['netmask'],
            'addr': netcard['addr'],
        }
    return ret


def socket_constants(prefix):
    return dict((getattr(socket, n), n) for n in dir(socket) if n.startswith(prefix))


SOCKET_FAMILIES = socket_constants('AF_')
SOCKET_TYPES = socket_constants('SOCK_')

# **********************************************************************************
# utils
# **********************************************************************************


def human_size(_bytes, traditional=((1024 ** 5, 'P'),
                                    (1024 ** 4, 'T'),
                                    (1024 ** 3, 'G'),
                                    (1024 ** 2, 'M'),
                                    (1024 ** 1, 'K'),
                                    (1024 ** 0, 'B'))):
    """Human-readable size"""
    for factor, suffix in traditional:
        if _bytes >= factor:
            amount = round(_bytes/factor, 2)
            return str(amount) + suffix
    else:
        return str(_bytes)


class Timer(object):

    def __init__(self, interval):
        self._interval = interval  # second
        self._st = time.time()

    def set_interval(self, interval):
        self._interval = interval

    def reset(self):
        self._st = time.time()

    def done(self):
        return (time.time() - self._st) >= self._interval


class Buffer(object):

    def __init__(self, size, atype='f'):
        self._atype = atype
        self._size = size
        self._items = array(atype, [])

    def size(self):
        return len(self._items)

    def append(self, item):
        if len(self._items) >= self._size:
            del self._items[0]
        self._items.append(item)

    def pre_items(self, x):
        return self._items[0:x].tolist()

    def xmean(self, x):
        return sum(self._items[0:x]) / x

    def preview(self):
        return self._items.tolist()

    def flush(self):
        self._items = array(self._atype, [])

    def mean(self):
        return sum(self._items) / len(self._items)

    def sum(self):
        return sum(self._items)


class ThreadActor(threading.Thread):

    def __init__(self, interval, name=''):
        super(ThreadActor, self).__init__(name=name)
        self.setDaemon(1)
        self._inbox = Queue()
        self._interval = interval
        self._timeout = None

    def _work(self):
        """Define in your subclass."""
        raise NotImplemented()

    def run(self):
        while True:
            try:
                msg = self._inbox.get(block=True, timeout=self._timeout)
                if msg == 'stop':
                    self._timeout = None
                elif msg == 'start':
                    self._timeout = self._interval
                elif msg == 'exit':
                    break
            except Empty:
                self._work()

    def start(self):
        self._inbox.put('start')
        return super(ThreadActor, self).start()

    def stop(self):
        self._inbox.put('stop')

    def shutdown(self):
        self._inbox.put('exit')


class ProcessActor(multiprocessing.Process):

    def __init__(self, interval, name=''):
        super(ProcessActor, self).__init__(name=name)
        self.daemon = True
        self._inbox = multiprocessing.Queue()
        self._interval = interval
        self._timeout = None

    def _work(self):
        """Define in your subclass."""
        raise NotImplemented()

    def run(self):
        while True:
            try:
                msg = self._inbox.get(block=True, timeout=self._timeout)
                if msg == 'stop':
                    self._timeout = None
                elif msg == 'start':
                    self._timeout = self._interval
                elif msg == 'exit':
                    break
            except Empty:
                self._work()

    def start(self):
        self._inbox.put('start')
        return super(ProcessActor, self).start()

    def stop(self):
        self._inbox.put('stop')

    def shutdown(self):
        self._inbox.put('exit')


class ThreadXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    pass


class XmlRpcServer(SimpleXMLRPCServer):
    allow_client_hosts = ('localhost', '127.0.0.1')

    def __init__(self, host, port):
        SimpleXMLRPCServer.__init__(self, (host, port), allow_none=True)

    def verify_request(self, request, client_address):
        return client_address[0] in self.allow_client_hosts


class TaskQueue(PriorityQueue):

    def add_task(self, task, block=True, timeout=None):
        self.put((task.priority, task), block=block, timeout=timeout)

    def pop_task(self, block=True, timeout=None):
        return self.get(block=block, timeout=timeout)[1]


class Node(object):

    def __init__(self, name):
        self.name = name
        self._service = None
        self._tasks = TaskQueue()

    def add_task(self, task):
        self._tasks.add_task(task)

    def get_task_queue(self):
        return self._tasks

    def _create_service(self):
        service = NodeService(self)
        return service

    def get_service(self):
        if not self._service:
            self._service = self._create_service()
        return self._service


class NodeService(object):

    def __init__(self, node):
        self.node = node

    def is_alive(self):
        return '*'

    def get_version(self):
        return __version__

    def get_psutil_version(self):
        return psutil.__version__

    def get_now(self):
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def get_boot_time(self):
        uptime = datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())
        return str(uptime).split('.')[0]

    def get_loadavg(self):
        return os.getloadavg()

    def get_system(self):
        _system = {
            'hostname': platform.node(),
            'os_name': platform.system(),
            'os_verbose': platform.platform(),
            'platform': platform.architecture()[0],
            'os_version': platform.release(),
        }
        linux_distro = platform.linux_distribution()
        if linux_distro[0] == '':
            _system['linux_distro'] = _linux_os_release()
        else:
            _system['linux_distro'] = ' '.join(linux_distro[:2])
        return _system

    def quicklook(self):
        return

    def get_netcard_info(self):
        return netcard_info()

    def add_task(self, task):
        pass

    def netstat(self, port):
        try:
            return subprocess.check_output('netstat -an | grep %s' % port, shell=True)
        except subprocess.CalledProcessError:
            logger.exception('netstat ERROR')
            return ''

    def path_exists(self, path):
        return os.path.exists(path)

    def makedirs(self, path):
        try:
            os.makedirs(path)
            return True
        except OSError:  # Permission denied
            return False

    def cat(self, path):
        pass

    def kill(self, pid):
        pass


class Agent(object):
    BIND_HOST = '0.0.0.0'
    PORT = 9001

    @classmethod
    def create_from_cli(cls):
        config = cls.handle_commandline()
        return cls(config)

    @staticmethod
    def handle_commandline():
        parser = argparse.ArgumentParser(description='xxx -- agent')
        parser.add_argument('-b', '--bind',
                            action='store', dest='host', default=None, metavar='host',
                            help='host to bind default to 0.0.0.0')
        parser.add_argument('-p', '--port',
                            action='store', type=int, dest='port', default=None, metavar='port',
                            help='port to listen default to 9001')
        parser.add_argument('-d', '--debug',
                            action='store_true', dest='debug', default=False,
                            help='start agent debug mode')
        return vars(parser.parse_args())

    def __init__(self, config):
        self.config = config
        hostname = socket.gethostname()
        self._service = Node(hostname).get_service()

    def _monitor_worker(self):
        pass

    def _task_worker(self):
        task_queue = self._service.node.get_task_queue()
        while True:
            task = task_queue.pop_task()
            try:
                task.do()
            except Exception as e:
                pass

    def _setup_workers(self):
        pass

    def _run_rpc(self):
        host = self.config['host'] or self.BIND_HOST
        port = self.config['port'] or self.PORT
        logger.info('Starting RPC-Server on %s:%s' % (host, port))
        self.server = XmlRpcServer(host, port)
        self.server.logRequests = self.config['debug']
        self.server.register_instance(self._service)
        return self.server.serve_forever()

    def run(self):
        logger.info('Starting agent...')
        self._setup_workers()
        return self._run_rpc()


logger = logging.Logger('agent')


def main():
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt='%(asctime)s : %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler('agent.log', mode='wb')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    agent = Agent.create_from_cli()
    if agent.config['debug']:
        logger.setLevel(logging.DEBUG)
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info('Goodbye!!!')


if __name__ == '__main__':
    main()
