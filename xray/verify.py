"""Validate generated profiles with the pinned official binary; no credentials printed."""
import hashlib,json,subprocess,tempfile,urllib.request,zipfile
from pathlib import Path
from configure import initialize
release=json.loads(Path(__file__).with_name('release.json').read_text())
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    with urllib.request.urlopen(f'https://github.com/XTLS/Xray-core/releases/download/{release["version"]}/Xray-linux-64.zip',timeout=60) as r:data=r.read(64*1024*1024)
    assert hashlib.sha256(data).hexdigest()==release['sha256']
    archive=root/'archive.zip';archive.write_bytes(data)
    with zipfile.ZipFile(archive) as z:(root/'xray').write_bytes(z.read('xray'))
    binary=root/'xray';binary.chmod(0o700)
    initialize(str(binary),root/'settings')
    for name in ('config.candidate.json','client.json'):
        result=subprocess.run([str(binary),'run','-test','-config',str(root/'settings'/name)],capture_output=True)
        if result.returncode:raise SystemExit('Generated Xray profile validation failed')
    print('Official checksum, server profile and client profile verified')
