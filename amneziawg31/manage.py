import sys,pathlib,subprocess,json,time
root=pathlib.Path('/opt/awg31')
def call(a,check=True):
 r=subprocess.run(a,capture_output=True,text=True)
 if check and r.returncode:raise RuntimeError('AWG31 operation failed: '+a[0])
 return r
rules=json.loads((root/'rules.json').read_text())
if sys.argv[1]=='up':
 for _ in range(100):
  if pathlib.Path('/var/run/amneziawg/awg31.sock').exists():break
  time.sleep(.1)
 call(['/usr/local/bin/awg31','setconf','awg31',str(root/'server.conf')])
 call(['ip','address','add','10.77.31.1/24','dev','awg31'])
 call(['ip','-6','address','add','fdc4:7731:4b90::1/64','dev','awg31'])
 call(['ip','link','set','dev','awg31','mtu','1280','up'])
 call(['sysctl','-w','net.ipv4.ip_forward=1'])
 call(['iptables','-w','-N','AWG31F'])
 for dst in ['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4']:
  call(['iptables','-w','-A','AWG31F','-i','awg31','-d',dst,'-j','REJECT'])
 call(['iptables','-w','-A','AWG31F','-i','awg31','-s','10.77.31.0/24','-o','eth0','-j','ACCEPT'])
 call(['iptables','-w','-A','AWG31F','-o','awg31','-d','10.77.31.0/24','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'])
 call(['iptables','-w','-A','AWG31F','-j','DROP'])
 for r in rules:
  base=[r['tool'],'-w','-t',r['table']]
  if call(base+['-C',r['chain']]+r['args'],False).returncode:call(base+(['-A',r['chain']] if r.get('append') else ['-I',r['chain'],'1'])+r['args'])
else:
 for r in reversed(rules):
  if r.get('append'):continue # Preserve baseline transit guard while forwarding stays enabled.
  base=[r['tool'],'-w','-t',r['table']]
  if not call(base+['-C',r['chain']]+r['args'],False).returncode:call(base+['-D',r['chain']]+r['args'])
 call(['iptables','-w','-F','AWG31F'],False)
 call(['iptables','-w','-X','AWG31F'],False)
 call(['ip','link','delete','awg31'],False)
