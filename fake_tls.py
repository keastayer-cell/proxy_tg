"""Fake TLS transport verification, matching Telegram MTProxy's authenticated handshake.

This is a probe only, not a general TLS implementation or certificate verifier.
The server is authenticated with the private MTProxy secret via HMAC-SHA256.
"""
import asyncio
import hashlib
import hmac
import ssl
import struct
import time


def client_hello(domain, secret):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    connection = context.wrap_bio(incoming, outgoing, server_hostname=domain)
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = bytearray(outgoing.read())
    if len(hello) < 517 or hello[:3] != b'\x16\x03\x01' or hello[43] != 32:
        raise ValueError('Unsupported probe ClientHello layout')
    hello[11:43] = bytes(32)
    digest = hmac.digest(secret, hello, hashlib.sha256)
    hello[11:43] = digest[:28] + struct.pack('<I', struct.unpack('<I', digest[28:])[0] ^ int(time.time()))
    return bytes(hello)


async def read_record(reader):
    header = await reader.readexactly(5)
    size = int.from_bytes(header[3:], 'big')
    if size > 18432:
        raise ValueError('Oversized Fake TLS record')
    return header + await reader.readexactly(size)


async def handshake(reader, writer, domain, secret):
    hello = client_hello(domain, secret)
    writer.write(hello)
    await writer.drain()
    records = [await read_record(reader) for _ in range(3)]
    if [record[0] for record in records] != [22, 20, 23]:
        raise ValueError('Unexpected Fake TLS server records')
    response = bytearray(b''.join(records))
    actual = response[11:43]
    response[11:43] = bytes(32)
    expected = hmac.digest(secret, hello[11:43] + response, hashlib.sha256)
    if not hmac.compare_digest(actual, expected):
        raise ValueError('Fake TLS server authentication failed')
    writer.write(b'\x14\x03\x03\x00\x01\x01')
    await writer.drain()


class RecordReader:
    def __init__(self, reader):
        self.reader, self.buffer = reader, bytearray()

    def __getattr__(self, name):
        return getattr(self.reader, name)

    async def readexactly(self, size):
        while len(self.buffer) < size:
            record = await read_record(self.reader)
            if record[:3] != b'\x17\x03\x03':
                raise ValueError('Unexpected Fake TLS data record')
            self.buffer.extend(record[5:])
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


class RecordWriter:
    def __init__(self, writer):
        self.writer = writer

    def __getattr__(self, name):
        return getattr(self.writer, name)

    def write(self, data):
        for start in range(0, len(data), 16384):
            chunk = data[start:start + 16384]
            self.writer.write(b'\x17\x03\x03' + len(chunk).to_bytes(2, 'big') + chunk)


def connection_type():
    from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate

    class FakeTLSConnection(ConnectionTcpMTProxyRandomizedIntermediate):
        tls_domain = None

        async def _connect(self, timeout=None, ssl=None):
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._ip, self._port), timeout=timeout)
            await handshake(self._reader, self._writer, self.tls_domain, self._secret)
            self._reader = RecordReader(self._reader)
            self._writer = RecordWriter(self._writer)
            self._codec = self.packet_codec(self)
            self._init_conn()
            await self._writer.drain()

    return FakeTLSConnection
