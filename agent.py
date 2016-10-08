#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division

import gevent
from gevent import monkey; monkey.patch_all()
from gevent.queue import PriorityQueue, Queue, Empty
from gevent import subprocess

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
from array import array
from SimpleXMLRPCServer import SimpleXMLRPCServer

import psutil
import netifaces


__version__ = '2.9.0'


# **********************************************************************************
# 配置
# **********************************************************************************

MARMOT_HOST = '192.168.162.91'
# MARMOT_HOST = '172.16.20.48'
MARMOT_PORT = 8100

IFNAME = 'eth0'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')
if not os.path.exists(SCRIPTS_DIR):
    os.mkdir(SCRIPTS_DIR)

ICE_PROJECT_DIR = '/tmp'
TOMCAT_DIR = '/tmp'


logger = logging.Logger('marmot-agent')
LOG_File = 'marmot-agent.log'

REDIS_LOG_URL = 'http://%s:%s/redis-log/' % (MARMOT_HOST, MARMOT_PORT)
CONF_URL = 'http://%s:%s/assets/server/conf/' % (MARMOT_HOST, MARMOT_PORT)
PROCESS_MONITOR_URL = 'http://%s:%s/assets/server/process-monitors/' % (MARMOT_HOST, MARMOT_PORT)
ALARM_URL = 'http://%s:%s/alarm/' % (MARMOT_HOST, MARMOT_PORT)

DEFAULT_CONF = {
    'monitor': {
        'enabled': False,
        'cpu': 99.0,
        'memory': 80,
        'disk': 90,
        'alarm_interval': 20,
    }
}


# **********************************************************************************
# 获取机器的静态信息
# **********************************************************************************

SYSTEM_PATTERN = re.compile(
    r'System Information\n\tManufacturer: (?P<manufacturer>.*)\n'
    r'\tProduct Name: (?P<product_name>.*)\n'
    r'\tVersion: (?P<version>.*)\n'
    r'\tSerial Number: (?P<serial_number>.*)\n'
    r'\tUUID: (?P<uuid>.*)\n'
    r'\t(.)*\n'
    r'\t(.)*\n'
    r'\tFamily: (?P<family>.*)\n'
)


def dmidecode_system():
    content = subprocess.check_output(['sudo', 'dmidecode'])
    match = re.search(SYSTEM_PATTERN, content)
    return {
        'manufacturer': match.group('manufacturer'),
        'product-name': match.group('product_name'),
        'version': match.group('version'),
        'serial-number': match.group('serial_number'),
        'uuid': match.group('uuid'),
        'family:': match.group('family'),
    }


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


def netcard_info():
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


def get_local_ip(ifname='eth0'):
    addrs = {}
    for iface_name in netifaces.interfaces():
        addresses = [i['addr'] for i in netifaces.ifaddresses(iface_name).setdefault(netifaces.AF_INET, [{'addr': None}])]
        addrs[iface_name] = addresses[0]
    return addrs[ifname]


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


class Alarm(object):
    """
    level: 1(一般), 2(中级), 3(严重)
    type: cpu, memory, disk, port, process
    """
    def __init__(self, host, type_, msg, level=1):
        self.host = host
        self.level = level
        self.type = type_
        self.msg = msg

    def message(self):
        return {
            'host': self.host,
            'level': self.level,
            'type': self.type,
            'msg': self.msg,
        }

    def __str__(self):
        return str(self.message())


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


class BaseMonitor(Actor):
    alarm_url = ALARM_URL

    def __init__(self, host, name=None, work_interval=5, alarm_interval=20):
        """
        work_interval: Second
        alarm_interval: Minutes
        """
        super(BaseMonitor, self).__init__(work_interval)
        self.host = host
        self.name = name or self.__class__.__name__
        self.alarm_countor = 0
        self.alarm_timer = Timer(60*alarm_interval)

    def reset_alarm_countor(self):
        self.alarm_countor = 0

    def increase_alarm_countor(self):
        self.alarm_countor += 1

    def set_alarm_interval(self, interval):
        """ interval: Minutes """
        self.alarm_timer.set_interval(60*interval)

    def _send_alarm(self, alarm):
        logger.info('%s: send alarm %s' % (self.name, alarm.message()))
        url = self.alarm_url + '?' + urllib.urlencode(alarm.message())
        req = urllib2.Request(url)
        res = urllib2.urlopen(req)
        return json.loads(res.read())

    def get_alarm(self):
        raise NotImplementedError

    def work(self):
        logger.debug('%s is running...' % self.name)
        alarm = self.get_alarm()
        if alarm:
            if self.alarm_countor:
                if self.alarm_timer.done():
                    self._send_alarm(alarm)
                    self.alarm_timer.reset()
            else:
                self._send_alarm(alarm)
                self.increase_alarm_countor()
                self.alarm_timer.reset()
        else:
            self.alarm_timer.reset()
            self.reset_alarm_countor()


class ProcessMonitor(BaseMonitor):
    process_monitor_url = PROCESS_MONITOR_URL

    def __init__(self, host, alarm_interval=20):
        super(ProcessMonitor, self).__init__(host, work_interval=10, alarm_interval=alarm_interval)

    @staticmethod
    def check_process(process):
        for p in psutil.process_iter():
            if process in ''.join(p.cmdline()):
                return True
        return False

    def _get_process_monitors(self):
        url = self.process_monitor_url + '?' + urllib.urlencode({'ip': self.host})
        req = urllib2.Request(url)
        res = urllib2.urlopen(req)
        return json.loads(res.read())['monitors']

    def get_alarm(self):
        try:
            monitors = self._get_process_monitors()
        except IOError:
            return
        if not monitors:
            return
        listening_ports = listening_port_set()
        for monitor in monitors:
            if not self.check_process(monitor['cmd']):
                return Alarm(
                    self.host, 'process',
                    '{0} - {1}: {2} - 进程: {3}未存活'.format(self.host, self.name, monitor['name'], monitor['process']),
                    level=3
                )
            if monitor['port'] not in listening_ports:
                return Alarm(
                    self.host, 'port',
                    '{0} - {1}: {2} - 端口: {3}未被占用'.format(self.host, self.name, monitor['name'], monitor['port']),
                    level=3
                )


class CpuMonitor(BaseMonitor):
    """
    Cpu负载监视器
    """
    def __init__(self, host, alarm_interval=20):
        super(CpuMonitor, self).__init__(host, work_interval=2, alarm_interval=alarm_interval)
        # 监控Actor的interval是2second, 这里缓冲1小时的数据, 即1800个数据
        self._buf = Buffer(1800)

    def load_avg(self):
        self._buf.append(psutil.cpu_percent())  # 刷新缓冲
        return {
            'avg10': self._buf.xmean(10 * 30),
            'avg30': self._buf.xmean(30 * 30),
            'avg60': self._buf.xmean(60 * 30),
        }

    def get_alarm(self):
        avg = self.load_avg()
        if avg['avg60'] >= 99.0:
            return Alarm(self.host, 'cpu', '{0} - {1}: Cpu负载已经持续1小时超过99%'.format(self.host, self.name), level=3)
        if avg['avg30'] >= 99.0:
            return Alarm(self.host, 'cpu', '{0} - {1}: Cpu负载已经持续30分钟超过99%'.format(self.host, self.name), level=2)
        if avg['avg10'] >= 99.0:
            return Alarm(self.host, 'cpu', '{0} - {1}: Cpu负载已经持续10分钟超过99%'.format(self.host, self.name), level=1)


class MemoryMonitor(BaseMonitor):
    """
    Memory监视器
    """
    def __init__(self, host, level=80, alarm_interval=20):
        super(MemoryMonitor, self).__init__(host, alarm_interval=alarm_interval)
        self._alarm_level = level
        self._buf = Buffer(6)

    def set_alarm_level(self, level):
        self._alarm_level = level

    def get_alarm(self):
        self._buf.append(psutil.virtual_memory().percent)
        used = self._buf.mean()
        if used >= self._alarm_level:
            return Alarm(self.host, 'memory', '{0} - {1}: 内存占用: {2}%'.format(self.host, self.name, used), level=2)


class DiskMonitor(MemoryMonitor):
    """
    Disk监视器
    """
    def get_alarm(self):
        for disk in disks():
            if disk['percent'] >= self._alarm_level:
                return Alarm(
                    self.host, 'disk',
                    '{0} - {1}: 挂载点: {2}, 使用: {3}%'.format(self.host, self.name, disk['mountpoint'], disk['percent']),
                    level=2
                )


class PortMonitor(BaseMonitor):
    """
    Port监视器
    """
    def __init__(self, host, alarm_interval=20):
        super(PortMonitor, self).__init__(host, alarm_interval=alarm_interval)
        self.allow_ports = set()  # 监听的端口
        self.deny_ports = set()  # 开放的端口 - 不允许被占用

    def set_allow_ports(self, ports):
        self.allow_ports = set(ports)

    def set_deny_ports(self, ports):
        self.deny_ports = set(ports)

    def get_alarm(self):
        listening_ports = listening_port_set()

        if self.allow_ports:
            if not (self.allow_ports < listening_ports):
                not_ports = self.allow_ports - listening_ports  # 监控端口列表中,没有被listen的端口
                return Alarm(self.host, 'port', '{0}: 监听端口{1}没有被监听'.format(self.host, not_ports), level=2)

        if self.deny_ports:
            tmp = self.deny_ports & listening_ports
            if tmp:
                return Alarm(self.host, 'port', '{0}: 开放端口{1}被占用'.format(self.host, tmp), level=1)


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


class DownloadMixin(object):
    def callback_progress(self, blocknum, blocksize, totalsize):
        percent = 100.0 * blocknum * blocksize / totalsize
        if percent > 100:
            percent = 100
        self.log('%.2f%%' % percent)

    def download_file(self, url, to_dir, fname=None):
        filename = os.path.join(to_dir, os.path.basename(url) if fname is None else fname)
        logger.info('Starting to download file: %s ...' % url)
        self.log('开始下载文件: %s ...' % url)
        try:
            urllib.urlretrieve(url, filename)
        except Exception as e:
            logger.exception('Download file fail: %s' % url)
            self.log('Download file error:' + str(e))
            return
        logger.info('Success to download file: %s' % url)
        self.log('下载完成: %s' % url)
        return filename


class TaskIceDeploy(DownloadMixin, TaskBase):
    def __init__(self, node_name, service_name, identifier, priority, jar, jar_md5, conf, conf_md5, pkg_dest_path):
        super(TaskIceDeploy, self).__init__(service_name, identifier, priority)
        self.node_name = node_name.encode('utf-8')
        self.jar = jar
        self.jar_md5 = jar_md5
        self.conf = conf
        self.conf_md5 = conf_md5
        self._pkg_dest_path = pkg_dest_path

    def header(self):
        return '{0} :: {1} :: '.format(self.node_name, time.strftime('%Y-%m-%d %H:%M:%S'))

    def download_jar(self):
        if self.jar:
            return self.download_file(self.jar, ICE_PROJECT_DIR)

    def download_conf(self):
        if self.conf:
            return self.download_file(self.conf, ICE_PROJECT_DIR)

    def deploy(self, jar, conf):
        if os.path.exists(self._pkg_dest_path):
            self.log('开始备份旧版本文件...')
            backup_dir(self._pkg_dest_path)
            clear_dir(self._pkg_dest_path)
            self.log('备份完成!')
        else:
            self.log('创建工程目录: %s' % self._pkg_dest_path)
            os.makedirs(self._pkg_dest_path)
        self.log('处理文件 ...')
        lib_path = os.path.join(self._pkg_dest_path, 'lib')
        os.mkdir(lib_path)
        shutil.move(jar, lib_path)
        if conf:
            unzip(conf, self._pkg_dest_path)
        self.log('文件处理完成...')
        self.log('>>>>>>>>>>>>>>>>完成<<<<<<<<<<<<<<<<<<')

    def do(self):
        jar = self.download_jar()
        conf = self.download_conf()
        if jar:
            self.check_md5(jar, self.jar_md5)
        if conf:
            self.check_md5(conf, self.conf_md5)
        if jar:
            self.deploy(jar, conf)
        else:
            self.log('jar包地址有误, 部署失败')


class TaskTomcatWar(DownloadMixin, TaskBase):
    def __init__(self, host, app_name, identifier, priority, war_url, war_md5, war_dir):
        super(TaskTomcatWar, self).__init__(app_name, identifier, priority)
        self.host = host
        self.war_url = war_url
        self.war_md5 = war_md5
        self.war_dir = war_dir

    def header(self):
        return '{0} :: {1} :: '.format(self.host, time.strftime('%Y-%m-%d %H:%M:%S'))

    def download_war(self):
        return self.download_file(self.war_url, TOMCAT_DIR, fname=self.name+'.war')

    def do(self):
        if not os.path.exists(self.war_dir):
            self.log('指定的War包目录不存在 %s' % self.war_dir)
            raise ValueError('ERROR: 指定的War包目录不存在 %s' % self.war_dir)

        war = self.download_war()
        if not os.path.isfile(war):
            self.log('ERROR: %s 文件不存在!' % os.path.basename(war))
            raise ValueError('ERROR: %s 文件不存在!' % os.path.basename(war))

        self.check_md5(war, self.war_md5)

        # 移除tomcat解压的war的目录
        real_war = os.path.join(self.war_dir, self.name)
        if os.path.exists(real_war):
            shutil.rmtree(real_war, ignore_errors=True)

        # 移除ROOT
        root_path = os.path.join(self.war_dir, 'ROOT')
        if os.path.exists(root_path):
            self.log('移除ROOT目录')
            shutil.rmtree(root_path, ignore_errors=True)

        self.log('移动War包到: %s' % self.war_dir)

        # 如果war包文件已经存在, 删除之
        if os.path.isfile(os.path.join(self.war_dir, os.path.basename(war))):
            self.log('该War包: %s 已经存在!' % os.path.join(self.war_dir, os.path.basename(war)))
            self.log('移除旧War包...')
            try:
                os.remove(os.path.join(self.war_dir, os.path.basename(war)))
            except OSError:  # Permission denied
                self.log('ERROR: 不能移除War包: %s Permission denied' % os.path.join(self.war_dir, os.path.basename(war)))
                raise
            self.log('旧War包已经移除')
            self.log('开始安装新War包')
        try:
            shutil.move(war, self.war_dir)
        except (IOError, shutil.Error) as e:
            self.log(unicode(e))
            raise
        self.log('>>>>>>>>>>>>>>>>完成<<<<<<<<<<<<<<<<<<')


class TaskCustomScript(TaskBase):
    def __init__(self, name, identifier, priority, script_url):
        super(TaskCustomScript, self).__init__(name, identifier, priority)
        self._script_url = script_url
        self._script_path = os.path.join(SCRIPTS_DIR, os.path.basename(self._script_url))

    def download_script(self):
        urllib.urlretrieve(self._script_url, self._script_path)
        return self._script_path

    def run_script(self):
        os.chmod(self._script_path, stat.S_IRWXU)
        old_dir = os.getcwd()
        os.chdir(SCRIPTS_DIR)
        p = subprocess.Popen(self._script_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.chdir(old_dir)
        return p

    def do(self):
        logger.info('Starting to download script: %s ...' % self._script_url)
        self.log('开始下载脚本: %s ...' % self._script_url)
        try:
            self.download_script()
        except IOError as e:
            logger.error('Download script fail: %s' % self._script_url)
            self.log(str(e))
            return
        else:
            logger.info('Success to download script: %s' % self._script_url)
            self.log('脚本下载完成: %s' % self._script_url)
        self.log('运行脚本...')
        self.run_script()
        self.log('脚本运行成功')


def task_factory(task_info):
    type_ = task_info.pop('type')
    if type_ == 'ice':
        return TaskIceDeploy(
            task_info['node_name'], task_info['name'], task_info['identifier'],
            task_info['priority'], task_info['jar'], task_info['jar_md5'],
            task_info['conf'], task_info['conf_md5'], task_info['pkg_dest_dir']
        )
    if type_ == 'tomcat':
        return TaskTomcatWar(
            task_info['host'], task_info['app_name'], task_info['identifier'],
            task_info['priority'], task_info['war_url'], task_info['war_md5'], task_info['war_dir']
        )
    if type_ == 'script':
        return TaskCustomScript(
            task_info['name'], task_info['identifier'], task_info['priority'],
            task_info['script_url']
        )


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
