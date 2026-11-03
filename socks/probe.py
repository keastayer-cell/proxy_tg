"""External SOCKS5 checks; credentials are read privately and never printed."""
import asyncio
from collections import defaultdict
import json
import logging
from pathlib import Path
import socket
import struct
import sys


def read_exact(sock, length):
    result=b''
    while len(result)<length:
        part=sock.recv(length-len(result))
        if not part:raise ConnectionError('SOCKS connection closed')
        result+=part
    return result


def authenticated_socket(credentials, password=None):
    sock=socket.create_connection((credentials['host'],credentials['port']),timeout=10)
    sock.settimeout(10)
    try:
        sock.sendall(b'\x05\x01\x02')
        if read_exact(sock,2)!=b'\x05\x02':raise PermissionError('Username authentication not selected')
        user=credentials['username'].encode()
        pwd=(credentials['password'] if password is None else password).encode()
        if not 1<=len(user)<=255 or not 1<=len(pwd)<=255:raise ValueError('Invalid authentication length')
        sock.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(pwd)])+pwd)
        if read_exact(sock,2)!=b'\x01\x00':raise PermissionError('Authentication rejected')
        return sock
    except BaseException:
        sock.close()
        raise


def connect_request(sock, host, port):
    sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(host)+struct.pack('>H',port))
    header=read_exact(sock,4)
    if header[:1]!=b'\x05':raise ValueError('Invalid SOCKS reply')
    if header[3]==1:read_exact(sock,6)
    elif header[3]==4:read_exact(sock,18)
    elif header[3]==3:read_exact(sock,read_exact(sock,1)[0]+2)
    else:raise ValueError('Invalid SOCKS address type')
    return header[1]


def open_telegram(credentials):
    sock=authenticated_socket(credentials)
    try:
        if connect_request(sock,'149.154.167.51',443)!=0:raise ConnectionError('Telegram destination rejected')
        return sock
    except BaseException:
        sock.close();raise


def negative_checks(credentials):
    with socket.create_connection((credentials['host'],credentials['port']),timeout=10) as sock:
        sock.settimeout(10)
        mss=sock.getsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG)
        sock.sendall(b'\x05\x01\x00')
        if read_exact(sock,2)!=b'\x05\xff':raise AssertionError('Anonymous access unexpectedly accepted')
        print('PASS: anonymous access rejected')
        print('INFO: client-reported TCP_MAXSEG',mss,'(server SYN-ACK MSS checked separately)')
    try:
        sock=authenticated_socket(credentials,credentials['password']+'x')
    except PermissionError:
        print('PASS: wrong password rejected')
    else:
        sock.close();raise AssertionError('Wrong password unexpectedly accepted')
    with authenticated_socket(credentials) as sock:
        if connect_request(sock,'1.1.1.1',443)==0:raise AssertionError('Non-Telegram destination unexpectedly allowed')
        print('PASS: authorized user cannot reach non-Telegram destinations')


async def telegram_check(credentials):
    from telethon.network.connection import ConnectionTcpAbridged
    from telethon.network.mtprotoplainsender import MTProtoPlainSender
    from telethon.network import authenticator
    class SocksConnection(ConnectionTcpAbridged):
        async def _connect(self, timeout=None, ssl=None):
            sock=await asyncio.to_thread(open_telegram,credentials)
            sock.setblocking(False)
            self._reader,self._writer=await asyncio.open_connection(sock=sock)
            self._codec=self.packet_codec(self)
            self._init_conn()
            await self._writer.drain()
    loggers=defaultdict(lambda:logging.getLogger('socks-probe'))
    connection=SocksConnection('149.154.167.51',443,2,loggers=loggers)
    try:
        await connection.connect(timeout=10)
        auth_key,_=await authenticator.do_authentication(MTProtoPlainSender(connection,loggers=loggers))
        assert len(auth_key.key)==256
        print('PASS: authenticated SOCKS5 traffic and full Telegram MTProto DH exchange')
    finally:await connection.disconnect()


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials-file',required=True)
    args=parser.parse_args()
    try:
        credentials=json.loads(Path(args.credentials_file).read_text())
        negative_checks(credentials)
        asyncio.run(asyncio.wait_for(telegram_check(credentials),timeout=40))
    except Exception as error:
        print('FAIL:',type(error).__name__)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
