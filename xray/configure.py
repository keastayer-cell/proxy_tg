"""Persistent VLESS+REALITY server configuration; all credentials stay on the VPS."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid
from urllib.parse import urlencode

PORT=2053
SNI='www.microsoft.com'


def server_config(c):
    uuid.UUID(c['uuid'])
    if not re.fullmatch('[0-9a-f]{16}',c['short_id']):raise ValueError('Invalid short ID')
    if len(base64.urlsafe_b64decode(c['private_key']+'='))!=32:raise ValueError('Invalid private key')
    return {
        'log':{'loglevel':'warning'},
        'inbounds':[{
            'tag':'personal-reality','listen':'0.0.0.0','port':PORT,'protocol':'vless',
            'settings':{'clients':[{'id':c['uuid'],'flow':'xtls-rprx-vision'}],'decryption':'none'},
            'streamSettings':{'network':'tcp','security':'reality','realitySettings':{
                'show':False,'target':SNI+':443','xver':0,'serverNames':[SNI],
                'privateKey':c['private_key'],'shortIds':[c['short_id']],
            }},
        }],
        'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'block'}],
        'routing':{'rules':[{'type':'field','ip':[
            '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
            '172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','::1/128','fc00::/7','fe80::/10'
        ],'outboundTag':'block'}]},
    }


def client_config(c,local_port=10890):
    return {
        'log':{'loglevel':'warning'},
        'inbounds':[{'tag':'local-socks','listen':'127.0.0.1','port':local_port,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],
        'outbounds':[{'tag':'reality','protocol':'vless','settings':{'vnext':[{
            'address':c['host'],'port':PORT,'users':[{'id':c['uuid'],'encryption':'none','flow':'xtls-rprx-vision'}]
        }]},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{
            'fingerprint':'chrome','serverName':SNI,'publicKey':c['public_key'],'shortId':c['short_id'],'spiderX':'/'
        }}}],
    }


def link(c):
    query=urlencode({'encryption':'none','security':'reality','sni':SNI,'fp':'chrome','pbk':c['public_key'],
                     'sid':c['short_id'],'type':'tcp','flow':'xtls-rprx-vision','spx':'/'})
    return f'vless://{c["uuid"]}@{c["host"]}:{PORT}?{query}#Amsterdam-REALITY'


def private_json(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.tmp')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as handle:json.dump(data,handle,indent=2)
    os.replace(temp,path)


def initialize(binary,directory='/etc/proxy_tg/xray'):
    directory=Path(directory);directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=directory/'credentials.json'
    if path.exists():
        credentials=json.loads(path.read_text())
    else:
        output=subprocess.check_output([binary,'x25519'],text=True,stderr=subprocess.PIPE)
        fields=dict(line.split(':',1) for line in output.splitlines() if ':' in line)
        fields={k.strip().lower().replace(' ',''):v.strip() for k,v in fields.items()}
        private=fields.get('privatekey')
        public=fields.get('publickey') or fields.get('password') or fields.get('password(publickey)')
        if not private or not public:raise ValueError('Unsupported Xray key generator output')
        credentials={'host':'178.62.199.241','uuid':str(uuid.uuid4()),'short_id':secrets.token_hex(8),
                     'private_key':private,'public_key':public}
        private_json(path,credentials)
    private_json(directory/'config.candidate.json',server_config(credentials))
    # The client profile contains no server private key.
    client={k:v for k,v in credentials.items() if k!='private_key'}
    private_json(directory/'client.json',client_config(client))
    private_json(directory/'client-credentials.json',client)
    fd=os.open(directory/'iphone.vless',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as handle:handle.write(link(client)+'\n')
    print('REALITY configuration ready; private keys and UUID hidden')


if __name__=='__main__':
    import sys
    try:initialize(sys.argv[1])
    except Exception as error:print('Configuration failed:',type(error).__name__);raise SystemExit(1)
