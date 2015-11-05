#!/usr/bin/env python
# encoding=utf-8

"""
ref: http://tools.ietf.org/html/rfc1928
"""

import socket
from threading import Thread, Lock
import sys
import os
import signal
import random
from optparse import OptionParser


VER = 0x05
METHOD = 0x00
REJECT = 0xFF

SUCCESS = 0x00
#SOCKFAIL = 0x01
#NETWORKFAIL = 0x02
NETWORKUNREACHABLE = 0x03
HOSTUNREACHABLE = 0x04
#HOSTFAIL = 0x04
#REFUSED = 0x05
#TTLEXPIRED = 0x06
UNSUPPORTCMD = 0x07
ADDRTYPEUNSPPORT = 0x08
UNASSIGNED = 0x09


CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP = 0x03


_LOGGER = None


class ClientError(Exception):
    pass


class Log:
    DEBUG = "debug"
    WARN = "WARN"
    INFO = "info"
    ERROR = "ERROR"

    def write(self, message, level):
        pass


class SimpleLog(Log):
    import sys

    def __init__(self, output=sys.stdout):
        self.__output = output
        self.show_log = True

    def write(self, message, level=Log.INFO):
        if level == Log.DEBUG:
            return
        if self.show_log:
            self.__output.write("%s:\t%s\n" % (level, str(message).strip()))


def getLogger(output=sys.stdout):
    global _LOGGER
    if not _LOGGER:
        _LOGGER = SimpleLog(output)
    return _LOGGER


class Address(object):
    IPv4 = 0x01
    DomainName = 0x03
    IPv6 = 0x04

    @classmethod
    def from_bytes(cls, get_bytes):
        address_type = get_bytes(1)[0]

        if address_type == cls.IPv4:
            host = get_bytes(4)
            port = get_bytes(2)
            return Address(host, port, address_type)
        elif address_type == cls.DomainName:
            name_len = get_bytes(1)[0]
            host = get_bytes(name_len)
            port = get_bytes(2)
            return Address(host, port, address_type)
        elif address_type == cls.IPv6:
            host = get_bytes(16)
            port = get_bytes(2)
            return Address(host, port, address_type)
        else:
            raise NotImplemented('Address type: %02X' % address_type)

    def __init__(self, host, port, type=None):
        if type is None:
            try:
                self.__host = self.__ip_to_bytes(host)
                self.__type = self.IPv4
            except ValueError:
                self.__host = self.__string_to_bytes(host)
                self.__type = self.DomainName
            self.__port = self.__int_to_bytes(int(port), 2)
        else:
            self.__type = type
            self.__host = host
            self.__port = port

    @property
    def bytes(self):
        ret = [self.__type]
        if self.__type == self.DomainName:
            ret += [len(self.__host)]
        ret += self.__host
        ret += self.__port
        return ret

    @property
    def host(self):
        return self.__str_host()

    @property
    def port(self):
        return self.__int_port()

    @property
    def type(self):
        return self.__type

    def __str__(self):
        return "%s:%d" % (self.__str_host(), self.__int_port())

    def __str_host(self):
        if self.__type == self.IPv4:
            addr = ".".join([str(b) for b in self.__host])
        elif self.__type == self.DomainName:
            addr = self.__bytes_to_string(self.__host)
        elif self.__type == self.IPv6:
            tmp = []
            for i in range(0, len(self.__host), 2):
                tmp.append('%02X%02X' % (self.__host[i], self.__host[i+1]))
            addr = '[%s]' % ':'.join(tmp)
        return addr

    @staticmethod
    def __bytes_to_string(bytes):
        string = ''
        for b in bytes:
            string += chr(b)
        return string

    @staticmethod
    def __string_to_bytes(string):
        bytes = []
        for c in string:
            bytes.append(ord(c))
        return bytes

    @staticmethod
    def __int_to_bytes(value, min_len=0):
        bytes = []
        while value:
            bytes.insert(0, value % 0x100)
            value /= 0x100
        while len(bytes) < min_len:
            bytes.insert(0, 0x00)
        return bytes

    @staticmethod
    def __ip_to_bytes(ip):
        bytes = []
        for octet in ip.split('.', 4):
            bytes.append(int(octet))
        return bytes

    def __int_port(self):
        return self.__port[0] * 0x100 + self.__port[1]


class Socks5Thread(Thread):

    def _sockid(self, sock):
        if not sock:
            return ''
        try:
            return '%s' % sock.fileno()
        except socket.error:
            return ''

    def __msg(self, msg, sock):
        sockid = self._sockid(sock)
        if sockid:
            sockid = ' (%s)' % sockid
        return '%s {%s}%s %s' % (self.__class__.__name__,
                                self.getName().split('-', 2)[1],
                                sockid,
                                msg)

    def debug(self, msg, sock=None):
        getLogger().write(self.__msg(msg, sock), Log.DEBUG)

    def info(self, msg, sock=None):
        getLogger().write(self.__msg(msg, sock), Log.INFO)

    def warning(self, msg, sock=None):
        getLogger().write(self.__msg(msg, sock), Log.WARN)

    def error(self, msg, sock=None):
        getLogger().write(self.__msg(msg, sock), Log.ERROR)

    def cleanup_socket(self, sock, msg=None):
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                if msg:
                    self.debug(' - cleanup %s' % msg, sock)
            except socket.error:
                pass


class SocketRepeater(Socks5Thread):
    __buf_size = 1024
    __timeout = 300

    def __init__(self, socks5http, src, dest):
        Thread.__init__(self)
        self.__socks5http = socks5http
        self.__src = src
        self.__dest = dest
        self.daemon = False

    def __del__(self):
        self.__cleanup()

    def __cleanup(self):
        self.cleanup_socket(self.__src, "src")
        self.__src = None

    def run(self):
        self.__socks5http.register(self)
        try:
            self.__handle_repeating()
        except Exception, e:
            self.error("(%s,%s) Repeater failed: %s" % (self._sockid(self.__src),
                                                        self._sockid(self.__dest),
                                                        e,))
        finally:
            self.__cleanup()
            self.__socks5http.checkout(self)

    def __handle_repeating(self):
        self.__src.settimeout(self.__timeout)
        #self.__src.setblocking(1)
        while True:
            data = self.__src.recv(self.__buf_size)
            if not data:
                break
            self.__dest.sendall(data)


class ClientHandler(Socks5Thread):
    __remote = None

    def __init__(self, socks5http, sock, proxy_lookup, bind=False):
        Thread.__init__(self)
        self.__socks5http = socks5http
        self.__local = sock
        self.__proxy_lookup = proxy_lookup
        # self.__bind = bind
        self.daemon = False


    def __del__(self):
        self.__cleanup()

    def __cleanup(self):
        self.cleanup_socket(self.__local, "local")
        self.__local = None

        self.cleanup_socket(self.__remote, "remote")
        self.__remote = None

    def run(self):
        self.__socks5http.register(self)
        try:
            self.__handle_client_connection()
        except (ClientError, socket.error), e:
            self.error("(%s,%s) %s" % (self._sockid(self.__local),
                                                       self._sockid(self.__remote),
                                                       e,))
        finally:
            self.__cleanup()
            self.__socks5http.checkout(self)

    def __handle_client_connection(self):
        ver, methods = self.__wait_greeting()
        self.debug("[%s] Greeting: ver=%d, methods=%s" % (self.getName(), ver, methods))

        if ver != VER or METHOD not in methods:
            self.__reject_methods()
            return

        self.__send_authtype()

        _, cmd, addr = self.__wait_connect_request()

        if addr.type == Address.IPv6:
            bytes = [VER, ADDRTYPEUNSPPORT, 0x00] + addr.bytes
            self.__put_bytes(bytes)
#            getLogger().write('IPv6 Addresses not supported: %s' % addr, Log.ERROR)
            return

        if cmd == CMD_BIND:
            raise ClientError('BIND command unsupported')
        elif cmd == CMD_UDP:
            raise ClientError('UDP command unsupported')
        elif cmd == CMD_CONNECT:
            self.info("open: %s" % addr, self.__local)
            self.__connect(addr)

        else:  #Unspport Command
            bytes = [VER, UNSUPPORTCMD, 0x00] + addr.bytes
            self.__put_bytes(bytes)

            raise ClientError('"%02X" command unsupported' % cmd)

    def __get_bytes(self, size):
        string = self.__local.recv(size)
        if len(string) != size:
            raise ClientError("Client didn't send expected data")
        bytes = []
        for ch in string:
            bytes.append(ord(ch))
        self.debug('->: %s' % ' '.join(['%02X' % b for b in bytes]))
        return bytes

    def __put_bytes(self, bytes):
        string = ''
        self.debug('<-: %s' % ' '.join(['%02X' % b for b in bytes]))
        for b in bytes:
            string += chr(b)
        self.__local.sendall(string)

    def __reject_methods(self):
        self.__put_bytes([VER, REJECT])

    def __wait_greeting(self):
        socks_ver, method_len = self.__get_bytes(2)
        methods = self.__get_bytes(method_len)
        return socks_ver, methods

    def __send_authtype(self):
        self.__put_bytes([VER, METHOD])

    def __wait_connect_request(self):
        socks_ver, cmd, reserved = self.__get_bytes(3)
        assert reserved == 0x00

        addr = Address.from_bytes(self.__get_bytes)

        return socks_ver, cmd, addr

    def __connect(self, addr):
        def hostunreachable():
            self.error('unable to establish connection to %s' % addr, self.__remote)
            bytes = [VER, HOSTUNREACHABLE, 0x00] + addr.bytes
            self.__put_bytes(bytes)

        for proxy in self.__proxy_lookup.gen_addresses(addr.host):
            dest = proxy or addr
            try:
                self.__remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.info('connect: %s' % dest,  self.__remote)
                self.__remote.connect((dest.host, dest.port))
                break
            except socket.error, e:
                self.error('connect: %s : %s' % (dest, e,), self.__remote)

                # 61: Connection refused
                if e.errno in (61,):
                    return hostunreachable()
        else:
            return hostunreachable()

        # if self.__bind:
        #     getLogger().write("Waiting for the client")
        #     self.sock, info = self.sock.accept()
        #     getLogger().write("Client connected")

        if proxy:
            connect = 'CONNECT %s:%d HTTP/1.0\r\n\r\n' % (addr.host, addr.port)
            self.debug("* -> %s" % connect)
            self.__remote.sendall(connect)

            # Waiting for: 'HTTP/1.0 200 Connection established\r\n\r\n'
            response = ''
            while True:
                response += self.__remote.recv(1)
                if response == 'HTTP/1.0 200 Connection established\r\n\r\n':
                    break
                if response[-4:] == '\r\n\r\n':
                    getLogger().write('HTTP Proxy Response: %s' % repr(response), Log.ERROR)
                    raise ValueError('Connection failed: %s' % response.rstrip())
            self.debug("* <- %s" % response)

        bytes = [VER, SUCCESS, 0x00] + addr.bytes
        self.__put_bytes(bytes)

        SocketRepeater(self.__socks5http, self.__local, self.__remote).start()
        SocketRepeater(self.__socks5http, self.__remote, self.__local).start()
        self.__local = None
        self.__remote = None


class ProxyAutoConfig(object):
    __pac_string = None
    __lock = Lock()

    def __init__(self, pac):
        if os.path.isfile(pac):
            self.__pac_string = open(pac).read()
        else:
            import urllib2
            response = urllib2.urlopen(pac)
            self.__pac_string = response.read()

    def find_proxy(self, host):
        self.__lock.acquire()
        try:
            import pacparser
            pacparser.init()
            pacparser.parse_pac_string(self.__pac_string)
            results = pacparser.find_proxy('http://%s' % host, host)
            pacparser.cleanup()

        finally:
            self.__lock.release()

        dests = []
        for result in results.split(';'):
            result = result.strip()
            if result.startswith('PROXY'):
                host, port = result.split(' ')[1].split(':')
                dests.append(Address(host, port))
            elif result.startswith('DIRECT'):
                dests.append(None)

        getLogger().write('Proxy for "%s" -> %s' % (host, dests), Log.DEBUG)
        return dests


class ProxyLookup(object):
    __dests = None

    def __init__(self):
        self.__dests = []
    __pac = None

    def add_proxy(self, dest):
        address = Address(*dest.split(':'))
        self.__dests.append(address)

    def add_pac(self, pac):
        pac = ProxyAutoConfig(pac)
        self.__dests.append(pac)

    def add_direct(self):
        self.__dests.append(None)

    def valid(self):
        return bool(self.__dests)

    def gen_addresses(self, host):
        used = []

        def result(value):
            if value in used:
                return
            yield value
            used.append(value)

        for dest in self.__dests:
            if isinstance(dest, Address):
                for r in result(dest): yield r
            elif isinstance(dest, ProxyAutoConfig):
                for address in dest.find_proxy(host):
                    for r in result(address): yield r
            elif dest is None:
                for r in result(dest): yield r


class Sock5Http(Socks5Thread):
    __sock = None
    __listener = None
    __proxy_lookup = None

    def __init__(self, bind, proxy_lookup):
        Thread.__init__(self)

        self.__bind = bind
        self.__proxy_lookup = proxy_lookup
        self.__residents = {}

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        self.cleanup_socket(self.__listener, 'listener')
        self.__listener = None

        for resident in self.__residents.values():
            del resident
        self.__residents = {}

    def register(self, object):
        self.__residents[object] = object

    def checkout(self, object):
        try:
            del self.__residents[object]
        except KeyError:
            pass

    def run(self):
        try:
            self.__listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__listener.bind((self.__bind.host, self.__bind.port))
        except socket.error, e:
            getLogger().write(e, Log.ERROR)
            return
        self.__listener.listen(10)

        self.info("Listening on %s" % (self.__bind,))

        while True:
            try:
                sock, addr_info = self.__listener.accept()
                self.info("accept: %s:%d" % addr_info, sock)
                ClientHandler(self, sock, self.__proxy_lookup).start()
            except ClientError, e:
                self.cleanup_socket(sock)
                getLogger().write(e.message, Log.ERROR)
            except KeyboardInterrupt:
                return


def main():
    proxy_lookup = ProxyLookup()

    def proxy_option(option, opt_str, value, parser):
        if opt_str == '--pac':
            proxy_lookup.add_pac(value)
        elif opt_str == '--http-proxy':
            proxy_lookup.add_proxy(value)
        elif opt_str == '--direct':
            proxy_lookup.add_direct()

    parser = OptionParser()
    parser.add_option('--bind',
        help=u'<ip:port> where service must listen')
    parser.add_option('--pac', action='callback', callback=proxy_option, type='string',
        help=u'<url | file> of Proxy Automatic Configuration')

    parser.add_option('--http-proxy', action='callback', callback=proxy_option, type='string',
        help=u'<host:port> of http proxy')

    parser.add_option('--direct', action='callback', callback=proxy_option,
        help=u'<host:port> of http proxy')

    parser.set_defaults(
        bind='0.0.0.0:8080',
    )

    options, args = parser.parse_args()

    bind = Address(*options.bind.split(':'))

    if not proxy_lookup.valid():
        getLogger().write('Invalid proxy configuration', Log.ERROR)
        exit(1)

    s = Sock5Http(bind, proxy_lookup)
    signal.signal(signal.SIGTERM, s.cleanup)
    try:
        s.run()
        try:
            s.join()
        except RuntimeError:
            pass
    finally:
        s.cleanup()


if __name__ == '__main__':
    exit(main())
