#!/usr/bin/env python3
"""Independent LP encoder + OpenSSL fixtures. Scalars1..4 are PUBLIC TEST KEYS.

Bodies/digests are deterministic. ECDSA envelope bytes change on explicit regeneration;
body identity must not. Never use these keys for an installation.
"""
import hashlib,json,struct,subprocess,tempfile
from pathlib import Path
OUT=Path(__file__).resolve().parent
F=lambda value:struct.pack('>I',len(value.encode() if isinstance(value,str) else value))+(value.encode() if isinstance(value,str) else value)
N=lambda value:F(struct.pack('>Q',value))
U=lambda value:F(struct.pack('>I',value))
H=lambda value:hashlib.sha256(value).digest()
FLEET='11111111-1111-1111-1111-111111111111';NODE='22222222-2222-2222-2222-222222222222';GRANT='33333333-3333-3333-3333-333333333333'
with tempfile.TemporaryDirectory(prefix='registration-golden-fixture-') as directory:
 root=Path(directory);points={}
 for scalar in range(1,5):
  # RFC5915 ECPrivateKey with explicit named P-256 curve; public point derived independently by OpenSSL.
  content=bytes.fromhex('0201010420')+scalar.to_bytes(32,'big')+bytes.fromhex('a00a06082a8648ce3d030107')
  key=root/f'{scalar}.der';key.write_bytes(bytes([0x30,len(content)])+content);key.chmod(0o600)
  public=subprocess.check_output(['openssl','ec','-inform','DER','-in',str(key),'-pubout','-conv_form','compressed','-outform','DER'],stderr=subprocess.DEVNULL)
  points[scalar]=public[-33:]
 def sign(scalar,message):
  body=root/'message';body.write_bytes(message)
  return subprocess.check_output(['openssl','dgst','-sha256','-keyform','DER','-sign',str(root/f'{scalar}.der'),str(body)],stderr=subprocess.DEVNULL)
 core=F('tessera-codes-contract/v1/device-registration-grant')+F(GRANT)+F(NODE)+F('fixture-org')+F(points[2])+N(1)+F('self-join-registration-v1')+F(bytes([0x44])*32)+N(100)+N(200)+N(500)+N(200)+U(1)+U(3)+F('pkcs12_envelope')+F(b'\x00')
 def authority(seq,grants):
  return F('tessera-codes-contract/v1/device-registration-authority')+F(FLEET)+F('fixture-owner')+N(seq)+N(90)+N(400)+U(len(grants))+b''.join(F(core)+F(mode)for mode in grants)
 bodies={'authority-empty':authority(6,[]),'authority-register':authority(7,['register']),'authority-verify-only':authority(8,['verify-only'])}
 hashes={}
 for name,body in bodies.items():
  (OUT/(name+'.body.hex')).write_text(body.hex()+'\n')
  (OUT/(name+'.wire')).write_text('tessera-codes/v1/device-registration-authority;body='+body.hex()+';owner_signature='+sign(1,body).hex()+'\n')
  hashes[name]={'bytes':len(body),'sha256':H(body).hex()}
 (OUT/'grant.body.hex').write_text(core.hex()+'\n');hashes['grant']={'bytes':len(core),'sha256':H(core).hex()}
 payload=F('77000123S')+F(points[3])+U(1)+U(1)+F('host')+F('fixture-1')+F('pkcs12_envelope')+F('none')+F('fixture-batch')+F(bytes([0xaa])*32)
 possession=sign(3,F('tessera-codes-contract/v1/proof-of-possession')+F(payload))
 organisation=sign(4,F('tessera-codes-contract/v1/registry-organisation')+F('fixture-org')+F(payload)+F(possession))
 proof=F('tessera-codes-contract/v1/registry-owner-delegated')+F(payload)+F(possession)+F('fixture-org')+F(organisation)+F('fixture-owner')+F(FLEET)+F(NODE)+F(GRANT)+F(H(core))+F(bytes([0xbb])*32)+F(bytes([0xcc])*32)+N(1)+F(b'')+N(120)+N(300)+N(7)
 signature=sign(2,proof)
 values=[('device','77000123S'),('key',points[3].hex()),('epoch','1'),('serials','host:fixture-1'),('key_protection','pkcs12_envelope'),('anchor','none'),('batch','fixture-batch'),('baseline',(bytes([0xaa])*32).hex()),('organisation','fixture-org'),('owner','fixture-owner'),('possession_signature',possession.hex()),('organisation_signature',organisation.hex()),('owner_proof','delegation-v1'),('fleet_id',FLEET),('tenant_node_id',NODE),('delegation_id',GRANT),('grant_digest',H(core).hex()),('request_digest',(bytes([0xbb])*32).hex()),('plan_digest',(bytes([0xcc])*32).hex()),('registration_generation','1'),('previous_record_digest','-'),('registered_at','120'),('not_after','300'),('authority_sequence_at_registration','7'),('delegate_signature',signature.hex())]
 owner_message=F('tessera-codes-contract/v1/registry-owner')+F('fixture-owner')+F(H(F(payload)+F(possession)+F(organisation)))
 (OUT/'legacy-record.wire').write_text('tessera-codes/v1/device-record'+''.join(';'+k+'='+v for k,v in values[:12])+';owner_signature='+sign(1,owner_message).hex()+'\n')
 (OUT/'record.wire').write_text('tessera-codes/v2/device-record'+''.join(';'+k+'='+v for k,v in values)+'\n')
 (OUT/'record.proof.hex').write_text(proof.hex()+'\n')
 hashes['record-proof']={'bytes':len(proof),'sha256':H(proof).hex()}
 hashes['record']={'sha256':H(F(proof)+F(signature)).hex()}
 (OUT/'hashes.json').write_text(json.dumps(hashes,indent=2)+'\n')
 (OUT/'public-keys.json').write_text(json.dumps({str(k):v.hex()for k,v in points.items()},indent=2)+'\n')
print(json.dumps(hashes,sort_keys=True))
