"""Fake TLS transport verification, matching Telegram MTProxy's authenticated handshake.

This is a probe only, not a general TLS implementation or certificate verifier.
The server is authenticated with the private MTProxy secret via HMAC-SHA256.
"""
import asyncio
import hashlib
import hmac
import secrets
import struct
import time


def client_hello(domain, secret):
    name = domain.encode('ascii')
    def extension(kind, payload):
        return kind.to_bytes(2, 'big') + len(payload).to_bytes(2, 'big') + payload
    server_name = b'\x00' + len(name).to_bytes(2, 'big') + name
    extensions = b''.join([
        extension(0, len(server_name).to_bytes(2, 'big') + server_name),
        extension(43, b'\x04\x03\x04\x03\x03'),
        extension(10, b'\x00\x04\x00\x1d\x00\x17'),
        extension(13, b'\x00\x08\x08\x04\x04\x03\x08\x05\x05\x03'),
        extension(51, b'\x00\x24\x00\x1d\x00\x20' + secrets.token_bytes(32)),
    ])
    prefix = b'\x03\x03' + bytes(32) + b'\x20' + secrets.token_bytes(32) + b'\x00\x06\x13\x01\x13\x02\x13\x03\x01\x00'
    padding = 508 - len(prefix) - 2 - len(extensions) - 4
    if padding < 0:
        raise ValueError('Fake TLS probe domain too long')
    extensions += extension(21, bytes(padding))
    body = prefix + len(extensions).to_bytes(2, 'big') + extensions
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    hello = bytearray(b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake)
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
