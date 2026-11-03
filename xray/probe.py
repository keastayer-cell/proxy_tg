import hashlib,json,os,secrets,socket,struct,subprocess,time,uuid,urllib.request,zipfile,sys,tempfile,shutil
from pathlib import Path
root=Path(tempfile.mkdtemp(prefix='xray-check-'))
(root/'client.json').write_bytes(Path(sys.argv[1]).read_bytes())
(root/'client.json').chmod(0o600)
profile=json.loads((root/'client.json').read_text())
profile['log']['loglevel']='debug'
(root/'client.json').write_text(json.dumps(profile))
redactions=[profile['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']]+[str(v) for k,v in profile['outbounds'][0]['streamSettings']['realitySettings'].items() if k in ('publicKey','shortId')]
log=open(root/'diagnostic.log','w+')
os.chmod(root/'diagnostic.log',0o600)
with socket.create_connection(('178.62.199.241',2053),timeout=8):pass
print('PASS public TCP 2053 reachable from independent VPS',flush=True)
assert 'privateKey' not in json.dumps(profile)
url='https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip'
with urllib.request.urlopen(url,timeout=60) as r: data=r.read(64*1024*1024)
assert hashlib.sha256(data).hexdigest()=='e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214'
(root/'archive.zip').write_bytes(data)
with zipfile.ZipFile(root/'archive.zip') as z: (root/'xray').write_bytes(z.read('xray'))
(root/'xray').chmod(0o700)
def curl(url,port=10890):
 return subprocess.run(['curl','--silent','--show-error','--fail','--max-time','20','--proxy',f'socks5h://127.0.0.1:{port}',url],capture_output=True,text=True)
def exact(s,n):
 b=b''
 while len(b)<n:
  part=s.recv(n-len(b))
  if not part:raise RuntimeError('Unexpected EOF')
  b+=part
 return b
processes=[]
try:
 p=subprocess.Popen([str(root/'xray'),'run','-config',str(root/'client.json')],stdout=log,stderr=log);processes.append(p)
 time.sleep(2)
 assert p.poll() is None,'Client process failed to start'
 r=curl('https://api.ipify.org');assert r.returncode==0 and r.stdout.strip()=='178.62.199.241',f'HTTPS exit test failed (curl {r.returncode})'
 print('PASS external REALITY + VLESS + HTTPS; exit IP 178.62.199.241',flush=True)
 for repeat in range(2):
  r=curl('https://api.ipify.org');assert r.returncode==0 and r.stdout.strip()=='178.62.199.241','Repeated HTTPS check failed'
 print('PASS three independent HTTPS sessions',flush=True)
 r=curl('https://api.telegram.org/');assert r.returncode==0,f'Telegram HTTPS failed (curl {r.returncode})'
 print('PASS Telegram HTTPS through REALITY with certificate verification',flush=True)
 with socket.create_connection(('127.0.0.1',10890),timeout=15) as s:
  s.settimeout(20);s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
  s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('149.154.167.51')+struct.pack('!H',443))
  h=exact(s,4);assert h[:2]==b'\x05\x00'
  if h[3]==1:exact(s,6)
  elif h[3]==4:exact(s,18)
  elif h[3]==3:exact(s,exact(s,1)[0]+2)
  nonce=secrets.token_bytes(16);body=struct.pack('<I',0xbe7e8ef1)+nonce
  packet=struct.pack('<qqi',0,int(time.time()*2**32)//4*4,len(body))+body
  s.sendall(b'\xef'+bytes([len(packet)//4])+packet)
  n=exact(s,1)[0]
  if n==127:n=int.from_bytes(exact(s,3),'little')
  answer=exact(s,n*4)
  assert answer[20:24]==struct.pack('<I',0x05162463) and answer[24:40]==nonce
 print('PASS real Telegram MTProto resPQ and matching nonce through REALITY',flush=True)
 profile['inbounds'][0]['port']=10891
 profile['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']=str(uuid.uuid4())
 bad=root/'invalid-client.json';bad.write_text(json.dumps(profile));bad.chmod(0o600)
 p=subprocess.Popen([str(root/'xray'),'run','-config',str(bad)],stdout=log,stderr=log);processes.append(p);time.sleep(1)
 r=curl('https://api.ipify.org',10891);assert r.returncode!=0,'Wrong UUID unexpectedly accepted'
 print('PASS incorrect VLESS UUID denied',flush=True)
except Exception:
 log.flush();log.seek(0);text=log.read()[-5000:]
 for value in redactions:text=text.replace(value,'<hidden>')
 print(text,flush=True)
 raise
finally:
 log.close()
 (root/'diagnostic.log').unlink(missing_ok=True)
 for p in processes:
  p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for name in ('client.json','invalid-client.json'):(root/name).unlink(missing_ok=True)

 shutil.rmtree(root)
