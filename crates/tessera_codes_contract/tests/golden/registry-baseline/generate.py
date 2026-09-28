#!/usr/bin/env python3
"""Independent public fixture encoder. Scalars1..4 are public TEST keys only.

Does not import Rust encoders or rewrite existing record/authority golden files.
Uses existing immutable legacy/delegated records as digest inputs. ECDSA envelope
bytes vary on deliberate regeneration; signed body identities do not.
"""
import hashlib,json,struct,subprocess,tempfile
from pathlib import Path
OUT=Path(__file__).resolve().parent
OLD=OUT.parent/'registration'
F=lambda x:struct.pack('>I',len(x.encode()if isinstance(x,str)else x))+(x.encode()if isinstance(x,str)else x)
N=lambda x:F(struct.pack('>Q',x));U=lambda x:F(struct.pack('>I',x));H=lambda x:hashlib.sha256(x).digest()
FLEET='11111111-1111-1111-1111-111111111111';NODE='22222222-2222-2222-2222-222222222222'
BASE='44444444-4444-4444-4444-444444444444';INSTANCE='55555555-5555-5555-5555-555555555555'
CUT='66666666-6666-6666-6666-666666666666';OP='77777777-7777-7777-7777-777777777777'
legacy=(OLD/'legacy-record.wire').read_text().strip().encode()
legacy_digest=H(legacy)
v2_digest=bytes.fromhex(json.loads((OLD/'hashes.json').read_text())['record']['sha256'])
def number(body):
 product=36
 for c in body:
  total=(product+int(c,36))%36 or 36
  product=(total*2)%37
 return body+'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[(37-product)%36]
def entry(num,state,generation,kind,digest):
 return F(num)+F(NODE)+F('fixture-org')+F(state)+N(generation)+F(kind)+F(digest)
def inventory(rows):return F('tessera-codes-contract/v1/registry-inventory')+U(len(rows))+b''.join(F(row)for row in rows)
inventories={
 'empty':inventory([]),
 'complete':inventory([
  entry('77000123S','current',1,'direct-v1-wire-sha256',legacy_digest),
  entry(number('77000124'),'retired',2,'delegated-v2-current-digest',v2_digest),
  entry(number('77000125'),'retired',1,'unknown',b''),
 ])}
def baseline(kind,inv):
 return F('tessera-codes-contract/v1/registry-baseline')+F(FLEET)+F('fixture-owner')+F(BASE)+F(INSTANCE)+F(CUT)+N(42)+F(bytes([0xaa])*32)+N(100)+N(200)+F('empty-history'if kind=='empty'else'complete-history')+U(0 if kind=='empty'else 3)+N(len(inv))+F(H(inv))
with tempfile.TemporaryDirectory(prefix='registry-baseline-fixtures-')as directory:
 root=Path(directory);content=bytes.fromhex('0201010420')+(1).to_bytes(32,'big')+bytes.fromhex('a00a06082a8648ce3d030107')
 key=root/'test-owner.der';key.write_bytes(bytes([0x30,len(content)])+content);key.chmod(0o600)
 def sign(body):
  path=root/'body';path.write_bytes(body)
  return subprocess.check_output(['openssl','dgst','-sha256','-keyform','DER','-sign',str(key),str(path)],stderr=subprocess.DEVNULL)
 def save(name,prefix,body):
  (OUT/(name+'.body.hex')).write_text(body.hex()+'\n')
  (OUT/(name+'.wire')).write_text(prefix+';body='+body.hex()+';owner_signature='+sign(body).hex()+'\n')
 hashes={}
 for kind,inv in inventories.items():
  (OUT/(kind+'.inventory.hex')).write_text(inv.hex()+'\n')
  body=baseline(kind,inv);save(kind,'tessera-codes/v1/registry-baseline',body)
  hashes[kind]={'body_bytes':len(body),'body_sha256':H(body).hex(),'inventory_bytes':len(inv),'inventory_sha256':H(inv).hex()}
 def companion(baseline_digest,state,generation,kind,old_digest):
  return F('tessera-codes-contract/v1/registry-import')+F(FLEET)+F('fixture-owner')+F(BASE)+F(baseline_digest)+F(INSTANCE)+F(OP)+F('77000123S')+F(NODE)+F('fixture-org')+N(120)+N(180)+F(state)+N(generation)+F(kind)+F(old_digest)+F(legacy_digest)
 for name,body in [
  ('import-new',companion(H(baseline('empty',inventories['empty'])),'absent',0,'none',b'')),
  ('import-replacement',companion(H(baseline('complete',inventories['complete'])),'current',1,'direct-v1-wire-sha256',legacy_digest))]:
  save(name,'tessera-codes/v1/registry-import',body);hashes[name]={'body_bytes':len(body),'body_sha256':H(body).hex()}
 # Existing direct-v1 device keys can be uncompressed P256 or P384. The owner
 # and organisation remain P256; both device signatures use SHA256 as in v1.
 for name,octets,oid,width in [('legacy-p256-uncompressed',32,'a00a06082a8648ce3d030107',65),('legacy-p384',48,'a00706052b81040022',97)]:
  content=bytes.fromhex('02010104')+bytes([octets])+(3).to_bytes(octets,'big')+bytes.fromhex(oid)
  device=root/'test-device.der';device.write_bytes(bytes([0x30,len(content)])+content);device.chmod(0o600)
  public=subprocess.check_output(['openssl','ec','-inform','DER','-in',str(device),'-pubout','-conv_form','uncompressed','-outform','DER'],stderr=subprocess.DEVNULL)[-width:]
  def key_signature(key_path,message):
   message_path=root/'record-message';message_path.write_bytes(message)
   return subprocess.check_output(['openssl','dgst','-sha256','-keyform','DER','-sign',str(key_path),str(message_path)],stderr=subprocess.DEVNULL)
  org_content=bytes.fromhex('0201010420')+(4).to_bytes(32,'big')+bytes.fromhex('a00a06082a8648ce3d030107')
  org=root/'test-org.der';org.write_bytes(bytes([0x30,len(org_content)])+org_content);org.chmod(0o600)
  payload=F('77000123S')+F(public)+U(1)+U(1)+F('host')+F('fixture-wide')+F('pkcs12_envelope')+F('none')+F('fixture-batch')+F(bytes([0xaa])*32)
  possession=key_signature(device,F('tessera-codes-contract/v1/proof-of-possession')+F(payload))
  organisation=key_signature(org,F('tessera-codes-contract/v1/registry-organisation')+F('fixture-org')+F(payload)+F(possession))
  owner=key_signature(key,F('tessera-codes-contract/v1/registry-owner')+F('fixture-owner')+F(H(F(payload)+F(possession)+F(organisation))))
  fields=[('device','77000123S'),('key',public.hex()),('epoch','1'),('serials','host:fixture-wide'),('key_protection','pkcs12_envelope'),('anchor','none'),('batch','fixture-batch'),('baseline',(bytes([0xaa])*32).hex()),('organisation','fixture-org'),('owner','fixture-owner'),('possession_signature',possession.hex()),('organisation_signature',organisation.hex()),('owner_signature',owner.hex())]
  record=('tessera-codes/v1/device-record'+''.join(';'+k+'='+v for k,v in fields)).encode()
  (OUT/(name+'.record.wire')).write_bytes(record+b'\n')
  body=F('tessera-codes-contract/v1/registry-import')+F(FLEET)+F('fixture-owner')+F(BASE)+F(H(baseline('empty',inventories['empty'])))+F(INSTANCE)+F(OP)+F('77000123S')+F(NODE)+F('fixture-org')+N(120)+N(180)+F('absent')+N(0)+F('none')+F(b'')+F(H(record))
  save(name+'-import','tessera-codes/v1/registry-import',body)
  hashes[name]={'record_bytes':len(record),'record_sha256':H(record).hex(),'public_point_bytes':len(public),'import_body_sha256':H(body).hex()}
 hashes['record_digests']={'direct-v1-wire-sha256':legacy_digest.hex(),'delegated-v2-current-digest':v2_digest.hex()}
 (OUT/'hashes.json').write_text(json.dumps(hashes,indent=2)+'\n')
print(json.dumps(hashes,sort_keys=True))
