#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# depends:
#  pip install pyip gevent greenlet
#

import gevent
import gevent.monkey

gevent.monkey.patch_all()

from gevent.threadpool import ThreadPool
from gevent.pool import Pool, Group
from optparse import OptionParser
from urllib2 import urlopen, HTTPError
from uuid import uuid4

import socket
import os
import ip
import icmp
import udp
import time
import json
import logging
import urlparse
import urllib


euid = os.geteuid()
MAX_RTT = 99                    # 99s
options = None


def update_url_query(url, **kwargs):
    result = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(result[4]))
    query.update(kwargs)
    result[4] = urllib.urlencode(query)
    return urlparse.urlunparse(result)


def file_split(f, delim='\n', bufsize=1024):
    prev = ''
    while True:
        s = f.read(bufsize)
        if not s:
            break
        split = s.split(delim)
        if len(split) > 1:
            yield prev + split[0]
            prev = split[-1]
            for x in split[1:-1]:
                yield x
        else:
            prev += s
    if prev:
        yield prev


def get_hostid(hostsconf):
    cdnid, diskid = '', ''
    for item in file_split(open(hostsconf), delim=';'):
        try:
            name, value = item.split(' ', 1)
            name = name.strip()
            if name == 'host_cdnid':
                cdnid = value.strip()
            elif name == 'host_diskid':
                diskid = value.strip()
        except Exception as e:
            logging.debug(e, exc_info=True)

    return cdnid, diskid


class Pinger(object):
    def __init__(self, bindaddr, peeraddr):
        self._peer = peeraddr
        self._connected = False
        self._sock = self.open_socket(bindaddr, peeraddr)
        self._type = self._sock.type

    def send(self, pkt_id, seq, data):
        buf = self.make_sending_data(pkt_id, seq, data)
        if self._connected:
            plen = self._sock.send(buf)
        else:
            plen = self._sock.sendto(buf, 0, self._peer)
        return plen

    def recv(self, pkt_id, seq, buflen=None):
        cond = lambda: True

        timeout = self._sock.gettimeout()
        if timeout:
            startup = time.time()
            cond = lambda: time.time() - startup < timeout

        while cond():
            try:
                buf = self._sock.recv(buflen or 65535)
                return self.extract_received_data(pkt_id, seq, buf)
            except (AssertionError, ValueError) as e:
                logging.debug(e, exc_info=True)

    def ping(self, pkt_id, seq, size, timeout):
        self._sock.settimeout(timeout)
        begtime = '%.6f' % time.time()
        headlen = len(begtime)
        restlen = max(size - headlen, 0)
        self.send(pkt_id, seq, begtime + '\0' * restlen)
        data, endtime = self.recv(pkt_id, seq), time.time()
        assert len(data) == headlen + restlen
        assert begtime == data[:headlen]
        rtt = endtime - float(begtime)
        return headlen + restlen, float('%.6f' % rtt)

    def open_socket(self, bindaddr=None, peeraddr=None):
        sock_type = socket.SOCK_RAW
        sock_proto = socket.IPPROTO_ICMP

        myeuid = os.geteuid()
        if myeuid or myeuid != euid:
            try:
                os.seteuid(euid)
                if euid and os.uname()[0] == 'Darwin':
                    sock_type = socket.SOCK_DGRAM
            except os.error:
                pass

        sock = socket.socket(socket.AF_INET,
                             sock_type,
                             sock_proto)
        os.setuid(os.getuid())      # drop privilege if any

        try:
            if bindaddr:
                if sock_type == socket.SOCK_DGRAM:
                    if hasattr(socket, 'SO_REUSEPORT'):
                        sock.setsockopt(socket.SOL_SOCKET,
                                        socket.SO_REUSEPORT,
                                        True)
                    sock.bind(bindaddr)
                elif sock_type == socket.SOCK_RAW:
                    # TODO: SO_BINDTODEVICE
                    pass
            if peeraddr:
                sock.connect(peeraddr)
                self._connected = True
        except Exception as e:
            logging.debug(e, exc_info=True)

        return sock

    def make_sending_data(self, pkt_id, seq, data):
        if self._type == socket.SOCK_DGRAM:
            udp_pkt = udp.Packet(sport=self._peer[1], data=data)
            data = udp.assemble(udp_pkt)

        if self._type in (socket.SOCK_RAW, socket.SOCK_DGRAM):
            icmp_pkt = icmp.Echo(id=pkt_id, seq=seq, data=data)
            return icmp.assemble(icmp_pkt)

        raise NotImplementedError(self._type)

    def extract_received_data(self, pkt_id, seq, data):
        if self._type in (socket.SOCK_RAW, socket.SOCK_DGRAM):
            ip_pkt = ip.disassemble(data)
            logging.debug(ip_pkt)
            icmp_pkt = icmp.disassemble(ip_pkt.data)
            logging.debug(icmp_pkt)
            assert icmp_pkt.get_type() == self.reply_type()
            assert icmp_pkt.get_id() == pkt_id

            if hasattr(self, 'pong_pool'):
                self.pong_pool[icmp_pkt.get_seq()] = icmp_pkt.get_data()
                logging.debug('pong pool size: %d', len(self.pong_pool))

            logging.debug('expect %d, actually %d', seq, icmp_pkt.get_seq())

            if hasattr(self, 'pong_pool') and seq in self.pong_pool:
                data = self.pong_pool[seq]
            else:
                assert icmp_pkt.get_seq() == seq
                data = icmp_pkt.get_data()
        else:
            raise NotImplementedError(self._type)

        if self._type == socket.SOCK_DGRAM:
            udp_pkt = udp.disassemble(data)
            logging.debug(udp_pkt)
            assert udp_pkt.sport == self._peer[1]
            data = udp_pkt.data

        return data

    def reply_type(self):
        return icmp.ICMP_ECHOREPLY


class PingHandler(object):
    def __init__(self, targets, concurrency=1000, pool=None, pinger=None):
        hosts, hostinfos = [], {}
        for k in targets:
            hostinfo = ip = k
            if isinstance(k, dict):
                cdnid, diskid, ip = str(k['cdnid']), str(k['diskid']), str(k['ip'])
                hostinfo = '-'.join([cdnid, diskid, ip])
            else:
                assert isinstance(k, str)

            hosts.append(ip)
            hostinfos[ip] = hostinfo

        self._hosts = hosts
        self._hostinfos = hostinfos
        self._port = 20000
        self._seq = 0
        self._id = os.getpid() & 0xffff
        self._pool = pool and pool(concurrency) or Pool(concurrency)

        pinger = pinger or Pinger
        pinger.pong_pool = {}
        self._pinger = pinger

    def get_port(self):
        port = self._port
        self._port += 1
        if self._port > 65535:
            self._port = 20000
        return port

    def get_seq(self):
        seq = self._seq
        self._seq += 1
        if self._seq > 65535:
            self._seq = 0
        return seq

    def handle_icmp(self, host, interval, count, size, timeout):
        ip = socket.gethostbyname(host.split(':')[0])
        rtts = [None] * count
        num_lost = [0]
        uuid = uuid4()

        def handle(index, size):
            lost, startup, rtt = 0, time.time(), MAX_RTT

            try:
                pkt_id, seq, port = self._id, self.get_seq(), self.get_port()
                pinger = self._pinger(('0.0.0.0', port), (ip, port))
                size, rtt = pinger.ping(pkt_id, seq, size, timeout)
            except Exception as e:
                logging.debug(e, exc_info=True)
                lost = 1
                num_lost[0] += 1
                rtt = time.time() - startup
            finally:
                rtts[index] = rtt
                self.once_icmp_replied(host, rtt, lost, seq, ip, size, uuid)
                gevent.sleep(interval)

        group = Group()
        for i in xrange(count):
            if interval == 0:
                group.add(gevent.spawn(handle, i, size))
            else:
                handle(i, size)

        if interval == 0:
            group.join()

        if count > 0:
            if num_lost[0] == count:
                avg_rtt = min_rtt = max_rtt = MAX_RTT
            else:
                avg_rtt = 0
                min_rtt, max_rtt = 2**32 - 1, -1
                for rtt in rtts:
                    if rtt is None:
                        continue

                    avg_rtt += rtt / count
                    if rtt < min_rtt:
                        min_rtt = rtt
                    if rtt > max_rtt:
                        max_rtt = rtt

                avg_rtt = float('%.6f' % avg_rtt)
                min_rtt = float('%.6f' % min_rtt)
                max_rtt = float('%.6f' % max_rtt)

            self.once_icmp_finished(host, count, count - num_lost[0],
                                    min_rtt, avg_rtt, max_rtt, uuid)

    def ping(self, interval=1, count=5, size=64, timeout=10):
        for host in self._hosts:
            self._pool.spawn(self.handle_icmp,
                             host, interval, count, size, timeout)

    def once_icmp_replied(self, host, rtt, lost, seq, ip, size, uuid):
        pass

    def once_icmp_finished(self, host, total, ok,
                           min_rtt, avg_rtt, max_rtt, uuid):
        pass


class MorePingHandler(PingHandler):
    def __init__(self, uris, *args, **kwargs):
        PingHandler.__init__(self, *args, **kwargs)
        self._uris = uris
        self._expect_messages = 0   # number of result messages will produce

    def ping_before(self):
        pass

    def ping_after(self):
        pass

    def ping(self,
             icmp_interval=1, icmp_count=5, icmp_size=64, icmp_timeout=10,
             http_interval=0, http_count=1, http_timeout=20):
        self.ping_before()
        for host in self._hosts:
            if icmp_count > 0:
                self._expect_messages += icmp_count + 1   # add an extra finished message
                self._pool.spawn(self.handle_icmp,
                                 host,
                                 icmp_interval,
                                 icmp_count,
                                 icmp_size,
                                 icmp_timeout)
            for uri in self._uris:
                if http_count > 0:
                    self._expect_messages += http_count + 1   # add an extra finished message
                    self._pool.spawn(self.handle_http,
                                     host,
                                     uri,
                                     http_interval,
                                     http_count,
                                     http_timeout)
        self.ping_after()

    def handle_http(self, host, uri, interval, count, timeout):
        num_ok = [0]
        speeds = [None] * count
        url = 'http://{host}{uri}'.format(host=host, uri=uri)
        uuid = uuid4()

        def handle(index):
            try:
                size = 0
                seq, startup = self.get_seq(), time.time()
                res = urlopen(url, timeout=timeout)
                while True:
                    chunk = res.read(8192)
                    if not chunk:
                        break
                    size += len(chunk)
                errcode = res.getcode()
                num_ok[0] += 1
            except HTTPError as e:
                logging.debug(e, exc_info=True)
                errcode = e.getcode()
            except Exception as e:
                logging.debug('%s: %s' % (url, e), exc_info=True)
                errcode = -1
            finally:
                rtt = time.time() - startup or 1e-6
                speed = int(size / rtt)
                speeds[index] = speed
                self.once_http_responsed(
                    host, speed, errcode, seq, uri, size, uuid)
                gevent.sleep(interval)

        group = Group()
        for i in xrange(count):
            if interval == 0:
                group.add(gevent.spawn(handle, i))
            else:
                handle(i)

        if interval == 0:
            group.join()

        if count > 0:
            if num_ok[0] == 0:
                avg_speed = min_speed = max_speed = 0
            else:
                avg_speed, min_speed, max_speed = 0, 2**32 - 1, -1
                for speed in speeds:
                    if speed is None:
                        continue

                    avg_speed += speed / count
                    if speed < min_speed:
                        min_speed = speed
                    if speed > max_speed:
                        max_speed = speed

                avg_speed = float('%.6f' % avg_speed)
                min_speed = float('%.6f' % min_speed)
                max_speed = float('%.6f' % max_speed)

            self.once_http_finished(host, count, num_ok[0],
                                    min_speed, avg_speed, max_speed, uuid)

    def once_http_responsed(self, host, speed, code, seq, uri, size, uuid):
        pass

    def once_http_finished(self, host, total, ok,
                           min_speed, avg_speed, max_speed, uuid):
        pass


class ConsolePinger(MorePingHandler):
    def __init__(self, *args, **kwargs):
        MorePingHandler.__init__(self, *args, **kwargs)

    def once_icmp_replied(self, host, rtt, lost, seq, ip, size, uuid):
        if lost == 1:
            return

        p = '{size} bytes from {host} ({ip}): icmp_seq={seq} time={rtt}ms'
        logging.info(p.format(size=size,
                              host=host,
                              ip=ip,
                              seq=seq,
                              rtt='%.3f' % (rtt * 1000)))

    def once_icmp_finished(self, host, total, ok,
                           min_rtt, avg_rtt, max_rtt, uuid):
        if ok == 0:
            loss = 100
        else:
            loss = (1 - float('%.4f' % (ok * 1.0 / total))) * 100

        p = '''
--- {host} ping statistics ---
{total} packets transmitted, {ok} packets received, {loss}% packet loss.'''
        logging.info(p.format(host=host, total=total, ok=ok, loss=loss))
        if loss < 100:
            logging.info('round-trip (ms)   min/avg/max = {min}/{avg}/{max}'.
                         format(min='%.3f' % (min_rtt * 1000),
                                avg='%.3f' % (avg_rtt * 1000),
                                max='%.3f' % (max_rtt * 1000)))

    def once_http_responsed(self, host, speed, code, seq, uri, size, uuid):
        if code != 200:
            return

        p = '{size} bytes from {host} ({uri}): http_seq={seq} speed={speed}kB/s'
        logging.info(p.format(size=size, host=host, uri=uri,
                              seq=seq,
                              speed='%.3f' % (speed / 1024.0)))

    def once_http_finished(self, host, total, ok,
                           min_speed, avg_speed, max_speed, uuid):
        if ok == 0:
            failed = 100
        else:
            failed = (1 - float('%.4f' % (ok * 1.0 / total))) * 100

        p = '''
--- {host} http statistics ---
{total} requests transmitted, {ok} requests succeeded, {failed}% requests failed.'''
        logging.info(p.format(
            host=host, total=total, ok=ok, failed=failed))
        if failed < 100:
            logging.info('speed (kB/s)   min/avg/max = {min}/{avg}/{max}'.
                         format(min='%.3f' % (min_speed / 1024.0),
                                avg='%.3f' % (avg_speed / 1024.0),
                                max='%.3f' % (max_speed / 1024.0)))


class ReportPinger(MorePingHandler):
    def __init__(self, source, uploads, timeout, *args, **kwargs):
        MorePingHandler.__init__(self, *args, **kwargs)

        def dns_parse(i):
            url = uploads[i]
            r = list(urlparse.urlparse(url))
            if r[1]:
                host_port = r[1].split(':', 1)
                rest = ''.join(host_port[1:])
                r[1] = socket.gethostbyname(host_port[0]) + (
                    rest if not rest
                    else (':' + rest))

                uploads[i] = urlparse.urlunparse(r)

        group = Group()
        for i in xrange(len(uploads)):
            group.add(gevent.spawn(dns_parse, i))
        group.join()

        self._uploads = uploads
        self._timeout = timeout

        if isinstance(source, dict):
            self._source = '-'.join([str(source['cdnid']),
                                     str(source['diskid']),
                                     str(source['ip'])])
        else:
            assert isinstance(source, str)
            self._source = source

    def once_icmp_replied(self, host, rtt, lost, seq, ip, size, uuid):
        # ms
        rtt = '%.3f' % (rtt * 1000)
        self.report(','.join([
            str('icmp'),
            str(self._source),
            str(self._hostinfos[host]),
            str(rtt),
            str(lost),
            str(seq),
            str(ip),
            str(size),
            str(int(time.time())),
            str(uuid),
        ]))

    def once_icmp_finished(self, host, total, ok,
                           min_rtt, avg_rtt, max_rtt, uuid):
        self.report(','.join([
            str('icmp-stat'),
            str(self._source),
            str(self._hostinfos[host]),
            str(total),
            str(ok),
            str('%.3f' % (min_rtt * 1000)),
            str('%.3f' % (avg_rtt * 1000)),
            str('%.3f' % (max_rtt * 1000)),
            str(int(time.time())),
            str(uuid),
        ]))

    def once_http_responsed(self, host, speed, code, seq, uri, size, uuid):
        # kB/s
        speed = '%.3f' % (speed / 1024.0)
        self.report(','.join([
            str('http'),
            str(self._source),
            str(self._hostinfos[host]),
            str(speed),
            str(code),
            str(seq),
            str(uri),
            str(size),
            str(int(time.time())),
            str(uuid),
        ]))

    def once_http_finished(self, host, total, ok,
                           min_speed, avg_speed, max_speed, uuid):
        self.report(','.join([
            str('http-stat'),
            str(self._source),
            str(self._hostinfos[host]),
            str(total),
            str(ok),
            str('%.3f' % (min_speed / 1024.0)),
            str('%.3f' % (avg_speed / 1024.0)),
            str('%.3f' % (max_speed / 1024.0)),
            str(int(time.time())),
            str(uuid),
        ]))

    def report(self, data):
        for target in self._uploads:
            self._pool.spawn(self.perform_report, target, data)

    def perform_report(self, target, data):
        # using short connection
        try:
            r = urlparse.urlparse(target)
            logging.debug(r)
            logging.debug(data)

            if r.scheme == 'udp':
                self.perform_report_udp(r.netloc, data)
            elif r.scheme == 'tcp':
                self.perform_report_tcp(r.netloc, data)
            elif r.scheme == 'unix':
                self.perform_report_unix(r.path, data)
            elif r.scheme in ('http', ''):
                self.perform_report_post(target, data)
            else:
                raise NotImplementedError(target)
        except Exception as e:
            logging.error('error(%s) for target: %s',
                          str(e), target, exc_info=True)

    def perform_report_udp(self, netloc, data):
        host_serv = netloc.split(':')
        host = host_serv[0]
        serv = int(80 if len(host_serv) == 1 else host_serv[1])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((host, serv))
        sock.sendall(data)
        sock.sendall('\n\n')    # end

    def perform_report_tcp(self, netloc, data):
        host_serv = netloc.split(':')
        host = host_serv[0]
        serv = int(80 if len(host_serv) == 1 else host_serv[1])
        sock = socket.create_connection((host, serv), timeout=self._timeout)
        sock.sendall(data)
        sock.sendall('\n\n')    # end

    def perform_report_unix(self, path, data):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        sock.sendall(data)
        sock.sendall('\n\n')    # end

    def perform_report_post(self, url, data):
        urlopen(url, data=data)


class KeepaliveReportPinger(ReportPinger):
    def __init__(self, *args, **kwargs):
        ReportPinger.__init__(self, *args, **kwargs)

    def ping_before(self):
        import gevent.queue
        self._queue = gevent.queue.Queue()

    def ping_after(self):
        for target in self._uploads:
            self._pool.spawn(self.perform_report, target)

    def report(self, data):
        self._queue.put(data)

    def perform_report(self, target):
        try:
            r = urlparse.urlparse(target)
            logging.debug(r)

            sender = None

            if r.scheme in ('udp', 'tcp'):
                host_serv = r.netloc.split(':')
                host = host_serv[0]
                serv = int(80 if len(host_serv) == 1 else host_serv[1])
                if r.scheme == 'udp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.connect((host, serv))
                    sender = sock.sendall
                elif r.scheme == 'tcp':
                    sock = socket.create_connection((host, serv), timeout=self._timeout)
                    if hasattr(socket, 'TCP_CORK'):
                        sock.setsockopt(socket.SOL_TCP, socket.TCP_CORK, 1)
                    sender = sock.sendall
            elif r.scheme == 'unix':
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(r.path)
                sender = sock.sendall
            else:
                raise NotImplementedError(target + ' on keepalive mode')

            assert callable(sender)

            for _ in xrange(self._expect_messages):
                data = self._queue.get()
                logging.debug(data)
                sender(data)
                sender('\n')
            sender('\n')    # end
        except Exception as e:
            logging.error('error(%s) for target: %s',
                          str(e), target, exc_info=True)


def check_iplist(iplistfile, expire):
    try:
        st = os.stat(iplistfile)
        old = json.load(open(iplistfile))
        return old, st.st_mtime + expire < time.time()
    except OSError:
        pass

    return None, True


def retrieve_cdnlist(domain, hostsconf, iplistfile, expire):
    ''' file format like below:
    {
        "source": {"cdnid": xxx, "diskid": xxx, "ip": xxx},
        "targets": [
            {"cdnid": xxx, "diskid": xxx, "ip": xxx},
            ...
        ],
        "includes": [
            {"cdnid": xxx, "diskid": xxx, "ip": xxx},
            ...
        ],
        "excludes": [
            {"cdnid": xxx, "diskid": xxx, "ip": xxx},
            ...
        ]
    }'''
    r, need_update = check_iplist(iplistfile, expire)
    if need_update:
        try:
            cdnid, diskid = get_hostid(hostsconf)
        except IOError:
            e = '''Could not load hostid from `%s`.
Please run with specific hosts, such as below:
    ping.py www.letv.com www.lecloud.com

Or re-run with a correct --hostsconf=PATH, whose content should be contains at least 2 elements:
    host_cdnid        XXX;
    host_diskid       XXX;''' % hostsconf
            raise Exception(e)

        url = update_url_query(domain, cdnid=cdnid, diskid=diskid)

        try:
            r = json.load(urlopen(url))
        except (HTTPError, ValueError) as e:
            if not r:  # request failed and no historical record found
                raise Exception('''%s on request `%s`.
Please check the FBS domain `%s` or hostsconf `%s`.''' % (
                    e, url, domain, hostsconf))
            else:
                logging.warn('%s: retrieve ip list from `%s` failed, '
                             'prefer the recently used records.',
                             e, url)
        else:
            try:
                json.dump(r, open(iplistfile, 'w'))
            except OSError as e:
                logging.error('Writing ip list failed: %s', e)

    source, targets = r['source'], []
    includes, excludes = r.get('includes', []), r.get('excludes', [])

    includes.extend(r['targets'])

    source_key = hash(tuple(source.values()))
    includes_set = set()
    excludes_set = set([hash(tuple(k.values())) for k in excludes])

    for k in includes:
        key = hash(tuple(k.values()))
        if key in excludes_set or key in includes_set or key == source_key:
            continue

        targets.append(k)
        includes_set.add(key)

    return source, targets


def main():
    parser = OptionParser(usage="usage: %prog [options] host...",
                          version="%prog 0.0.4")
    parser.add_option("-d", "--destination",
                      action="append",
                      metavar="URL",
                      dest="dest",
                      help="destination URLs to report")
    parser.add_option("-t", "--ping-timeout",
                      dest="ping_timeout",
                      default=10,
                      type=float,
                      help="time in second to ping each host")
    parser.add_option("-T", "--download-timeout",
                      dest="download_timeout",
                      default=20,
                      type=float,
                      help="time in second to download each file")
    parser.add_option("-w", "--wait-timeout",
                      dest="wait_timeout",
                      default=10,
                      type=float,
                      help="time in minute to wait all requests finish")
    parser.add_option("-u", "--upload-timeout",
                      dest="upload_timeout",
                      default=60,
                      type=float,
                      help="time in second to upload each testing result")
    parser.add_option("-i", "--ping-interval",
                      type=float,
                      default=0,
                      help="interval of ping for each host")
    parser.add_option("-I", "--download-interval",
                      type=float,
                      default=0,
                      help="interval of download for each file")
    parser.add_option("-s", "--ping-size",
                      type=int,
                      default=64,
                      help="size of message to ping for each host")
    parser.add_option("-n", "--ping-count",
                      type=int,
                      default=5,
                      help="ping count for each host")
    parser.add_option("-N", "--download-count",
                      type=int,
                      default=1,
                      help="download count for each host")
    parser.add_option("-f", "--file",
                      action="append",
                      metavar="URI",
                      help="file URI to test download speed")
    parser.add_option("-C", "--concurrency",
                      type=int,
                      default=1000,
                      help="concurrency limit")
    parser.add_option("--ready",
                      type=int,
                      default=300,
                      help="hanging up at `ready`-based second to ready run")
    parser.add_option("--debug",
                      action="store_true",
                      default=False,
                      help="enable debug logging")
    parser.add_option("--thread",
                      action="store_true",
                      default=False,
                      help="enable thread-pooled ping")
    parser.add_option("--keepalive",
                      action="store_true",
                      default=False,
                      help="using long connection on upload, doesn't support http")
    parser.add_option("--fbs-domain",
                      type=str,
                      default='http://greenping.cdn.lecloud.com/fbs/get/iplist',
                      help="domain to fetch target hosts")
    parser.add_option("--hostsconf",
                      type=str,
                      default='/usr/local/etc/hosts.conf',
                      help="configure file to load cdnid and diskid")
    parser.add_option("--iplist-file",
                      type=str,
                      default='/var/tmp/ping_iplist',
                      help="file to save ip list that fetched from FBS")
    parser.add_option("--iplist-expire",
                      type=int,
                      default=12 * 3600,
                      help="time in second to cache the ip list")

    global options
    options, args = parser.parse_args()

    if options.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format='[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')

    source = ''
    uploads = options.dest or []
    upload_timeout = options.upload_timeout
    uris = options.file or []
    targets = args or []

    if not targets:
        source, targets = retrieve_cdnlist(options.fbs_domain,
                                           options.hostsconf,
                                           options.iplist_file,
                                           options.iplist_expire)
        if options.ready > 0:
            second = hash(tuple(source.values())) % options.ready
            logging.debug("working at %d second later", second)
            time.sleep(second)

    if uploads:
        Reporter = ReportPinger
        if options.keepalive:
            Reporter = KeepaliveReportPinger

        pinger = Reporter(source, uploads, upload_timeout, uris, targets,
                          concurrency=options.concurrency,
                          pool=options.thread and ThreadPool)
    else:
        pinger = ConsolePinger(uris, targets,
                               concurrency=options.concurrency,
                               pool=options.thread and ThreadPool)

    pinger.ping(icmp_interval=options.ping_interval,
                icmp_timeout=options.ping_timeout,
                icmp_size=options.ping_size,
                icmp_count=options.ping_count,
                http_interval=options.download_interval,
                http_timeout=options.download_timeout,
                http_count=options.download_count)

    gevent.wait(timeout=options.wait_timeout * 60)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.error(e, exc_info=options.debug if options else False)
