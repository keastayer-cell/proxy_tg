"""End-to-end MTProto handshake without a Telegram account or API credentials."""
import asyncio
from collections import defaultdict
import logging
import os
import secrets
from proxy import load_env, settings


async def probe():
    from telethon.network.connection import ConnectionTcpMTProxyRandomizedIntermediate
    from telethon.network.mtprotoplainsender import MTProtoPlainSender
    from telethon.tl.functions import ReqPqMultiRequest
    from telethon.tl.types import ResPQ
    host, port, _, secret = settings(os.environ)
    loggers = defaultdict(lambda: logging.getLogger('probe'))
    connection = ConnectionTcpMTProxyRandomizedIntermediate(
        '149.154.167.51', 443, 2, loggers=loggers,
        proxy=(host, port, 'dd' + secret),
    )
    try:
        await connection.connect(timeout=10)
        nonce = int.from_bytes(secrets.token_bytes(16), 'little', signed=True)
        response = await MTProtoPlainSender(connection, loggers=loggers).send(ReqPqMultiRequest(nonce))
        if not isinstance(response, ResPQ) or response.nonce != nonce:
            raise ValueError('Invalid Telegram handshake')
        print('OK: Telegram MTProto handshake through proxy')
    finally:
        await connection.disconnect()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', required=True)
    args = parser.parse_args()
    try:
        load_env(args.env_file)
        asyncio.run(asyncio.wait_for(probe(), timeout=20))
    except Exception as error:
        print('FAIL:', type(error).__name__)
        raise SystemExit(1)
