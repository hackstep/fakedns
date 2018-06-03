import re
import io
import socket
import datetime
import argparse
from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server

class FakeQuery(dns.Query, object):
    hostname = None
    def __init__(self, name=b'', type=dns.A, cls=dns.IN, hostname=None):
        self.name = dns.Name(name)
        self.type = type
        self.cls = cls
        self.hostname = hostname
    def __cmp__(self, other):
        if isinstance(other, dns.Query) or isinstance(other, FakeQuery):
            return cmp(
                (str(self.name).lower(), self.type, self.cls),
                (str(other.name).lower(), other.type, other.cls))
        return NotImplemented

class FakeResolverChain(server.resolve.ResolverChain, object):
    def lookupAddress(self, name, timeout=None, hostname=None):
        return self._lookup(name, dns.IN, dns.A, timeout, hostname)

    def lookupIPV6Address(self, name, timeout=None, hostname=None):
        return self._lookup(name, dns.IN, dns.AAAA, timeout, hostname)

    def _lookup(self, name, cls, type, timeout, hostname=None):
        if not self.resolvers:
            return defer.fail(error.DomainError())
        q = FakeQuery(name, type, cls, hostname)
        d = self.resolvers[0].query(q, timeout)
        for r in self.resolvers[1:]:
            d = d.addErrback(
                server.resolve.FailureHandler(r.query, q, timeout)
            )
        return d

    def query(self, query, timeout=None):
        try:
            method = self.typeToMethod[query.type]
        except KeyError:
            self._log.debug(
                'Query of unknown type {query.type} for {query.name.name!r}',
                query=query)
            return defer.maybeDeferred(
                self._lookup, query.name.name, dns.IN, query.type, timeout, query.hostname)
        else:
            return defer.maybeDeferred(method, query.name.name, timeout, query.hostname)

class FakeDNSServerFactory(server.DNSServerFactory, object):
    def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
        resolvers = []
        if authorities is not None:
            resolvers.extend(authorities)
        if caches is not None:
            resolvers.extend(caches)
        if clients is not None:
            resolvers.extend(clients)

        self.canRecurse = not not clients
        self.resolver = FakeResolverChain(resolvers)
        self.verbose = verbose
        if caches:
            self.cache = caches[-1]
        self.connections = []

    def messageReceived(self, message, proto, address=None):
        if address:
            clinentAddr = address
        else:
            clinentAddr = proto.transport.client

        for query in message.queries:
            print('['+str(datetime.datetime.now())+'] ' + str(clinentAddr[0]) + ':' + str(clinentAddr[1]) + ' asks for ' + dns.QUERY_TYPES[query.type] + ' ' + query.name.name)

        super(FakeDNSServerFactory, self).messageReceived(message, proto, address)

    def handleQuery(self, message, protocol, address):
        query = message.queries[0]
        query.hostname = protocol.transport.socket.getsockname()[0]
        if query.hostname == '0.0.0.0':
            query.hostname = socket.gethostbyname(socket.gethostname())

        return self.resolver.query(query).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )

class FakeResolver(object):
    def __init__(self):
        f = open('./hosts','r')
        lines = f.readlines()
        f.close()

        self._domains = dict()
        for line in lines:
            ip,domain = line.split()
            if not self._domains.has_key(domain):
                self._domains[domain]=[ip]
            else:
                self._domains[domain].append(ip)

    def _isIPv4(self, address):
        try:
            socket.inet_pton(socket.AF_INET, address)
            return True
        except AttributeError:
            try:
                socket.inet_aton(address)
                return True
            except socket.error:
                return False
        except socket.error:
            return False

    def _isIPv6(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False

    def _fillAnswer(self, query, value):
        if value == 'self' or value == 'host':
            return query.hostname
        else:
            return value

    def _buildResponse(self, query):
        name = query.name.name.lower()
        resps = []

        for pattern,values in self._domains.items():
            if pattern.startswith('/'):
                if re.search(pattern.strip('/'), name):
                    for value in values:
                        resps.append(self._fillAnswer(query, value))
                    break
            else:
                if pattern == name:
                    for value in values:
                        resps.append(self._fillAnswer(query, value))
                    break

        if len(resps) > 0:
            answers = []
            authority = []
            additional = []

            for resp in resps:
                if query.type == dns.A:
                    if self._isIPv4(resp):
                        answers.append(
                            dns.RRHeader(
                                name=name,
                                payload=dns.Record_A(address=resp)))
                elif query.type == dns.AAAA:
                    if self._isIPv6(resp):
                        answers.append(
                            dns.RRHeader(
                                name=name,
                                type=dns.AAAA,
                                payload=dns.Record_AAAA(address=resp)))
                else:
                    return None
            return answers, authority, additional
        else:
            return None

    def query(self, query, timeout=None):
        resp = self._buildResponse(query)

        if resp:
            return defer.succeed(resp)
        else:
            return defer.fail(error.DomainError())

def get_args():
    parser = argparse.ArgumentParser(
        description='Fake DNS server')
    parser.add_argument("-a", "--address", default='0.0.0.0', 
                    help="address listen to")
    parser.add_argument("-p", "--port", default=53, type=int,
                    help="port listen to")
    args = parser.parse_args()
    return args.address, args.port

def main():
    address, port = get_args()
    print('Starting server on ' + address + ':' + str(port) + '...')
    factory = FakeDNSServerFactory(
        clients=[FakeResolver(), client.Resolver(resolv='/etc/resolv.conf')]
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    reactor.listenUDP(port, protocol, interface=address)
    reactor.listenTCP(port, factory, interface=address)
    reactor.run()

if __name__ == '__main__':
    raise SystemExit(main())
