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
import stat
import signal
import logging
import argparse
import subprocess
from array import array
from SimpleXMLRPCServer import SimpleXMLRPCServer

import psutil
import netifaces


__version__ = '0.0.1'


# **********************************************************************************
# 获取机器的静态信息
# **********************************************************************************

VENDOR_PATTERN = re.compile(r'vendor_id([ \t])+: (?P<vendor_id>.*)\n')
MODEL_PATTERN = re.compile(r'model name([ \t])+: (?P<model_name>.*)\n')


def cpu_info():
    with open('/proc/cpuinfo') as f:
        content = f.read()
    return {
        'vendor': re.search(VENDOR_PATTERN, content).group('vendor_id').strip(),
        'model': re.search(MODEL_PATTERN, content).group('model_name').strip(),
        'core_num': psutil.cpu_count(logical=True),
    }


def get_hwaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def netcard():
    interfaces = netifaces.interfaces()
    if 'lo' in interfaces:
        interfaces.remove('lo')
    ret = {}
    for i in interfaces:
        try:
            netcard = netifaces.ifaddresses(i)[netifaces.AF_INET][0]
        except KeyError:
            continue

        ret[i] = {
            'mac': get_hwaddr(i),
            'broadcast': netcard['broadcast'],
            'mask': netcard['netmask'],
            'addr': netcard['addr'],
        }
    return ret


def socket_constants(prefix):
    return dict((getattr(socket, n), n) for n in dir(socket) if n.startswith(prefix))


SOCKET_FAMILIES = socket_constants('AF_')
SOCKET_TYPES = socket_constants('SOCK_')


def base_info():
    return {
        'hostname': socket.gethostname(),
        'system': dmidecode_system(),
        'os_distribution': '-'.join(platform.linux_distribution()),
        'os_verbose': platform.platform(),
        'cpu_info': cpu_info(),
        'disk_size': '%sG' % disk_total()['total'],
        'memory_total': memory()['total'],
    }


# **********************************************************************************
# runtime info
# **********************************************************************************


def users():
    user_list = []
    for u in psutil.users():
        user_list.append({
            'name': u.name,
            'terminal': u.terminal,
            'host': u.host,
            'started': datetime.datetime.fromtimestamp(u.started).strftime('%Y-%m-%d %H:%M:%S'),
        })
    return user_list


def memory():
    data = psutil.virtual_memory()
    divisor = 1024**3
    return {
        'total': '%.2fG' % (data.total/divisor),
        'available': '%.2fG' % (data.available/divisor),
        'used': '%.2fG' % (data.used/divisor),
        'free': '%.2fG' % (data.free/divisor),
        'percent': '{}%'.format(data.percent),
        'shared': '%.2fG' % (data.shared/divisor) if hasattr(data, 'shared') else '0',
        'active': '%.2fG' % (data.active/divisor),
        'inactive': '%.2fG' % (data.inactive/divisor),
        'buffers': '%.2fG' % (data.buffers/divisor),
        'cached': '%.2fG' % (data.cached/divisor),
    }


def swap_memory():
    sm = psutil.swap_memory()
    divisor = 1024**3
    return {
        'total': '%.2fG' % (sm.total/divisor),
        'free': '%.2fG' % (sm.free/divisor),
        'used': '%.2fG' % (sm.used/divisor),
        'percent': '{}%'.format(sm.percent),
        'swapped_in': '%.2fG' % (sm.sin/divisor),
        'swapped_out': '%.2fG' % (sm.sout/divisor),
    }


def cpu():
    cpu_times = psutil.cpu_times_percent(0)
    return {
        'user': cpu_times.user,
        'system': cpu_times.system,
        'idle': cpu_times.idle,
        'iowait': cpu_times.iowait,
        'load_avg': os.getloadavg(),
    }


def disk_total():
    disk_data = disks(all_partitions=True)
    space_total = round(sum([i['total'] for i in disk_data]), 2)
    space_used = round(sum([i['used'] for i in disk_data]), 2)
    return {
        'total': space_total,
        'used': space_used,
        'free': round(sum([i['free'] for i in disk_data]), 2),
        'percent': round((space_used/space_total)*100, 2),
    }


def disks(all_partitions=False):
    divisor = 1024**3
    dks = []
    for dp in psutil.disk_partitions(all_partitions):
        usage = psutil.disk_usage(dp.mountpoint)
        disk = {
            'device': dp.device,
            'mountpoint': dp.mountpoint,
            'type': dp.fstype,
            'options': dp.opts,
            'total': round((usage.total/divisor), 2),
            'used': round((usage.used/divisor), 2),
            'free': round((usage.free/divisor), 2),
            'percent': usage.percent,
        }
        dks.append(disk)
    return dks


def disks_counters(perdisk=True):
    return {dev: c._asdict() for dev, c in psutil.disk_io_counters(perdisk=perdisk).iteritems()}


def net_io_counters():
    return psutil.net_io_counters()._asdict()


def net_connections():
    return psutil.net_connections()


def process_list():
    p_list = []
    for p in psutil.process_iter():
        mem = p.memory_info()
        # psutil throws a KeyError when the uid of a process is not associated with an user.
        try:
            username = p.username()
        except KeyError:
            username = None

        proc = {
            'pid': p.pid,
            'name': p.name(),
            'cmdline': ' '.join(p.cmdline()),
            'user': username,
            'status': p.status(),
            'created': p.create_time(),
            'mem_rss': mem.rss,
            'mem_vms': mem.vms,
            'mem_percent': p.memory_percent(),
            'cpu_percent': p.cpu_percent(0)
        }
        p_list.append(proc)

    return p_list


def connections(filters=None):
    filters = filters or {}
    conns = []
    for c in psutil.net_connections('all'):
        conn = {
            'fd': c.fd,
            'pid': c.pid,
            'family': SOCKET_FAMILIES[c.family],
            'type': SOCKET_TYPES[c.type],
            'local_addr_host': c.laddr[0] if c.laddr else None,
            'local_addr_port': c.laddr[1] if c.laddr else None,
            'remote_addr_host': c.raddr[0] if c.raddr else None,
            'remote_addr_port': c.raddr[1] if c.raddr else None,
            'state': c.status
        }
        for k, v in filters.iteritems():
            if v and conn.get(k) != v:
                break
        else:
            conns.append(conn)
    return conns


def listening_port_set():
    ports = set()
    for c in psutil.net_connections('all'):
        if c.laddr:
            port = c.laddr[1]
            if isinstance(port, int):
                ports.add(port)
    return ports


# **********************************************************************************
# Monitor
# **********************************************************************************


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


class Actor(gevent.Greenlet):

    def __init__(self, interval):
        super(Actor, self).__init__()
        self._inbox = Queue()
        self._interval = interval
        self._timeout = None

    def work(self):
        """
        Define in your subclass.
        """
        raise NotImplemented()

    def _run(self):
        while True:
            try:
                msg = self._inbox.get(block=True, timeout=self._timeout)
                if msg == 'stop':
                    self._timeout = None
                elif msg == 'start':
                    self._timeout = self._interval
                elif msg == 'shutdown':
                    break
            except Empty:
                try:
                    self.work()
                except Exception:
                    logger.exception('UnknowError')
            gevent.sleep(0)

    def start(self):
        self._inbox.put('start')
        return super(Actor, self).start()

    def stop(self):
        self._inbox.put('stop')

    def shutdown(self):
        self._inbox.put('shutdown')


# **********************************************************************************
# Marmot
# **********************************************************************************


def http_get_json(url, param=None):
    if param:
        url = url + '?' + urllib.urlencode(param)
    req = urllib2.Request(url)
    res = urllib2.urlopen(req)
    return json.loads(res.read())


def http_post_json(url, data):
    req = urllib2.Request(url, json.dumps(data))
    res = urllib2.urlopen(req)
    return json.loads(res.read())


def zip_dir(dirname, zfname=None):
    if zfname is None:
        zfname = os.path.basename(os.path.normpath(dirname)) + '.zip'
    zf = zipfile.ZipFile(zfname, 'w', zipfile.ZIP_DEFLATED, allowZip64=True)
    base_len = len(dirname)
    for root, dirs, files in os.walk(dirname):
        for f in files:
            fn = os.path.join(root, f)
            zf.write(fn, fn[base_len:])
        for d in dirs:
            fn = os.path.join(root, d)
            zf.write(fn, fn[base_len:])
    zf.close()


def unzip(filename, to_dir):
    zf = zipfile.ZipFile(filename, 'r')
    zf.extractall(to_dir)
    zf.close()


def backup_dir(dirname):
    dt = time.strftime('%Y-%m-%d-%H-%M-%S')
    base, name = os.path.split(dirname)
    bak_dir = os.path.join(base, 'bak')
    if not os.path.exists(bak_dir):
        os.mkdir(bak_dir)
    return zip_dir(dirname, os.path.join(bak_dir, 'bak-{0}-{1}.zip'.format(name, dt)))


def clear_dir(dirname):
    for path in os.listdir(dirname):
        filepath = os.path.join(dirname, path)
        if os.path.isfile(filepath):
            os.remove(filepath)
        elif os.path.isdir(filepath):
            shutil.rmtree(filepath, ignore_errors=True)


class TaskQueue(PriorityQueue):
    def add_task(self, task, block=True, timeout=None):
        self.put((task.priority, task), block=block, timeout=timeout)

    def pop_task(self, block=True, timeout=None):
        return self.get(block=block, timeout=timeout)[1]


class TaskBase(object):
    def __init__(self, name, identifier, priority):
        logger.info('Construct Task: %s uuid: %s ...' % (name, identifier))
        self.name = name
        self.identifier = identifier
        self.priority = int(priority)
        self._log_init()

    def header(self):
        return '{} :: '.format(time.strftime('%Y-%m-%d %H:%M:%S'))

    def check_md5(self, fname, md5):
        self.log('MD5校验: %s ...' % os.path.basename(fname))
        if hashlib.md5(open(fname, 'rb').read()).hexdigest() == md5:
            self.log('MD5校验 - %s, 文件: %s' % ('OK', os.path.basename(fname)))
        else:
            self.log('MD5校验 - %s, 文件: %s' % ('FAILED', os.path.basename(fname)))
            raise ValueError('MD5校验 - %s, 文件: %s' % ('FAILED', os.path.basename(fname)))

    def _log_init(self):
        return http_post_json(REDIS_LOG_URL, {
            'act': 'init',
            'id': self.identifier,
        })

    def log(self, info):
        return http_post_json(REDIS_LOG_URL, {
            'act': 'log',
            'id': self.identifier,
            'msg': self.header() + info
        })

    def do(self):
        raise NotImplementedError


class XmlRpcServer(SimpleXMLRPCServer):
    allow_client_hosts = (MARMOT_HOST, 'localhost', '127.0.0.1', '10.20.0.202')

    def __init__(self, host, port):
        SimpleXMLRPCServer.__init__(self, (host, port), allow_none=True)

    def verify_request(self, request, client_address):
        return client_address[0] in self.allow_client_hosts


class Node(object):
    def __init__(self, ip):
        self._service = None
        self._ip = ip
        self._tasks = TaskQueue()
        self.cpu_monitor = CpuMonitor(self._ip)
        self.memory_monitor = MemoryMonitor(self._ip)
        self.disk_monitor = DiskMonitor(self._ip)
        self.process_monitor = ProcessMonitor(self._ip)

    @property
    def id(self):
        return self._ip

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

    def set_memory_monitor_level(self, level):
        logger.info('Set memory-monitor alarm level: %s' % level)
        self.node.memory_monitor.set_alarm_level(level)

    def set_disk_monitor_level(self, level):
        logger.info('Set disk-monitor alarm level: %s' % level)
        self.node.disk_monitor.set_alarm_level(level)

    def set_alarm_interval(self, interval):
        logger.info('Set alarm interval: %s' % interval)
        self.node.cpu_monitor.set_alarm_interval(interval)
        self.node.memory_monitor.set_alarm_interval(interval)
        self.node.disk_monitor.set_alarm_interval(interval)
        self.node.process_monitor.set_alarm_interval(interval)

    def start_monitor(self):
        logger.info('Start monitors...')
        self.node.cpu_monitor.start()
        self.node.memory_monitor.start()
        self.node.disk_monitor.start()
        self.node.process_monitor.start()

    def stop_monitor(self):
        logger.info('Stop monitors...')
        self.node.cpu_monitor.stop()
        self.node.memory_monitor.stop()
        self.node.disk_monitor.stop()
        self.node.process_monitor.stop()

    def add_task(self, task_info):
        logger.info('Received task: %s' % task_info)
        try:
            task = task_factory(task_info)
        except Exception:
            logger.exception('add task error: %s' % task_info['identifier'])
            return False
        if task:
            self.node.add_task(task)
            logger.info('Added task: %s' % task.name)
            return True

    def netstat(self, port):
        try:
            return subprocess.check_output('netstat -an | grep %s' % port, shell=True)
        except subprocess.CalledProcessError:
            logger.exception('netstat ERROR')
            return ''

    def get_es_info(self, url):
        try:
            req = urllib2.Request(url)
            resp = urllib2.urlopen(req)
            return resp.read()
        except Exception:
            logger.exception('Get ES info ERROR')
            return ''

    def path_exists(self, path):
        return os.path.exists(path)

    def create_path(self, path):
        try:
            os.makedirs(path)
            return True
        except OSError:  # Permission denied
            return False

    def kill_process(self, cmd):
        logger.info('Received task: kill process - %s' % cmd)
        cmd_flag = os.path.sep.join(cmd.split(os.path.sep)[:3])
        for p in psutil.process_iter():
            cmdline = ''.join(p.cmdline())
            if cmd_flag in cmdline and 'java' in cmdline:
                try:
                    p.kill()
                    return True
                except psutil.AccessDenied:
                    ret = os.system('sudo su - www -c "kill -9 %s"' % p.pid)
                    if ret == 0:
                        logger.info('Kill process - %s SUCCESS' % cmd)
                        return True
                    else:
                        logger.info('Kill process - %s FAILS -- AccessDenied' % cmd)
                        return False
        logger.info('Kill process - %s FAIL. The process is not exists!' % cmd)
        return False

    def tomcat_is_alive(self, cmd):
        cmd_flag = os.path.sep.join(cmd.split(os.path.sep)[:3])
        for p in psutil.process_iter():
            cmdline = ''.join(p.cmdline())
            if cmd_flag in cmdline and 'java' in cmdline:
                return True
        return False

    def start_tomcat(self, cmd):
        logger.info('Received task: Start tomcat - %s' % cmd)
        # ret = os.system('sudo su - www -c "%s"' % cmd)
        ret = os.system(cmd)
        if ret == 0:
            logger.info('Start tomcat - %s SUCCESS' % cmd)
            return True
        else:
            logger.info('Start tomcat - %s FAIL' % cmd)
            return False

    def is_alive(self):
        return True

    def get_base_info(self):
        return base_info()

    def get_netcard_info(self):
        return netcard_info()

    def get_runtime_info(self):
        return {
            'hostname': socket.gethostname(),
            'users': users(),
            'cpu': cpu(),
            'memory': memory(),
            'swap': swap_memory(),
            'disks': disks(),
            'uptime': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
        }

    def get_processes_info(self):
        return process_list()


class MarmotAgent(object):
    BIND_HOST = '0.0.0.0'
    PORT = 9001

    @classmethod
    def create_from_cli(cls):
        config = cls.handle_commandline()
        local_ip = get_local_ip(ifname=IFNAME)
        if local_ip is None:
            logger.error('Can not get local ip')
            raise OSError
        logger.info('Local ip: %s' % local_ip)
        try:
            conf = http_get_json(CONF_URL, {'ip': local_ip})
        except IOError:
            logger.warning('Can not get node config - %s' % CONF_URL)
            conf = DEFAULT_CONF
        conf['ip'] = local_ip
        config.update(conf)
        return cls(config)

    @staticmethod
    def handle_commandline():
        parser = argparse.ArgumentParser(description='Marmot -- agent')
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
        self.monitor_conf = self.config.pop('monitor')
        self._service = Node(self.config.pop('ip')).get_service()
        if self.monitor_conf:
            self._service.set_memory_monitor_level(self.monitor_conf['memory'])
            self._service.set_disk_monitor_level(self.monitor_conf['disk'])
            self._service.set_alarm_interval(self.monitor_conf['alarm_interval'])
            if self.monitor_conf['enabled']:
                self._service.start_monitor()

    def _task_worker(self):
        logger.info('Starting task-worker...')
        task_queue = self._service.node.get_task_queue()
        while True:
            task = task_queue.pop_task()
            logger.info('Start run task: %s' % task.name)
            try:
                task.do()
            except Exception as e:
                task.log("出错啦！ - " + unicode(e))
                logger.exception('Task: %s error' % task.name)

    def _setup_workers(self):
        gevent.spawn_later(1, self._task_worker)

    def _run_rpc(self):
        host = self.config['host'] or self.BIND_HOST
        port = self.config['port'] or self.PORT
        logger.info('Starting Marmot RPC-Server on %s:%s' % (host, port))
        self.server = XmlRpcServer(host, port)
        self.server.logRequests = self.config['debug']
        self.server.register_instance(self._service)
        return self.server.serve_forever()

    def run(self):
        logger.info('Starting Marmot agent...')
        self._setup_workers()
        return self._run_rpc()


def main():
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt='%(asctime)s : %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(LOG_File, mode='w')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    agent = MarmotAgent.create_from_cli()
    if agent.config['debug']:
        logger.setLevel(logging.DEBUG)
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info('Goodbye!!!')


if __name__ == '__main__':
    gevent.signal(signal.SIGQUIT, gevent.kill)
    main()
    lskdfjlaskdflss
    sldkflskdjf'

    sldkflsdfj
