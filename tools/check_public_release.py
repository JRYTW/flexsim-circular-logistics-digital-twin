"""Portable release checks. Reports rule IDs and file names, never matched secrets."""
from pathlib import Path
import csv
import ast
import hashlib
import io
import json
import re
import sys
import urllib.parse
import zipfile
import zlib
import gzip
import sqlite3
from xml.etree import ElementTree as ET

RULES = {
    'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    'github_token': r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b',
    'openai_token': r'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b',
    'aws_access_id': r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'google_api_key': r'\bAIza[A-Za-z0-9_-]{30,}\b',
    'slack_token': r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b',
    'credential_assignment': r'''(?i)["']?(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)["']?\s*[:=]\s*["'][A-Za-z0-9_./+\-=]{12,}["']''',
    'email_address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'user_home_path': r'(?i)(?:[A-Z]:[\\/]+Users[\\/]+|/(?:Users|home)/)[^\s"<>]+',
    'local_absolute_path': r'(?i)\b[A-Z]:[\\/]+(?:Program Files|Windows|Temp|Users)[\\/ ]',
    'file_uri': r'(?i)file:/+',
    'loopback_endpoint': r'(?i)\b(?:localhost|127\.0\.0\.1)\b',
    'private_ipv4': r'\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b',
}
COMPILED = {name: re.compile(pattern) for name, pattern in RULES.items()}
BLOCKED_SUFFIXES = {'.fsm','.fsx','.sqlite','.db','.pem','.key','.pfx','.p12','.log','.env','.bak'}
ALLOWED_SUFFIXES = {'.md','.csv','.json','.py','.pptx','.png','.webm'}
ALLOWED_BASENAMES = {'LICENSE','.gitignore','.gitattributes'}
SKIP_DIRS = {'.git','__pycache__'}

def inspect_text(name,text,issues):
    normalized=urllib.parse.unquote(text).replace('\\\\','\\')
    for rule,pattern in COMPILED.items():
        if pattern.search(normalized):issues.append({'file':name,'rule':rule})

def inspect_office(name,data,issues):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if z.testzip():issues.append({'file':name,'rule':'invalid_zip'})
        for member in z.namelist():
            b=z.read(member)
            if member.endswith(('.xlsx','.pptx','.docx')):inspect_office(name+'!'+member,b,issues)
            elif member.endswith(('.xml','.rels','.svg','.vml')):
                ET.fromstring(b)
                inspect_text(name+'!'+member,b.decode('utf8'),issues)

def inspect_media(name,data,issues):
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        offset=8
        while offset+12<=len(data):
            size=int.from_bytes(data[offset:offset+4],'big')
            kind=data[offset+4:offset+8];payload=data[offset+8:offset+8+size]
            if kind==b'tEXt':inspect_text(name+'!PNG-text',payload.decode('latin1'),issues)
            elif kind==b'zTXt':
                key,rest=payload.split(b'\0',1)
                inspect_text(name+'!PNG-text',(key+b' '+zlib.decompress(rest[1:])).decode('utf8',errors='replace'),issues)
            elif kind==b'iTXt':
                key,rest=payload.split(b'\0',1);compressed=rest[0];rest=rest[2:]
                language,rest=rest.split(b'\0',1);translated,text=rest.split(b'\0',1)
                if compressed:text=zlib.decompress(text)
                inspect_text(name+'!PNG-text',(key+b' '+translated+b' '+text).decode('utf8',errors='replace'),issues)
            offset+=size+12
        return
    # Parse EBML metadata, excluding encoded video packets whose random bytes
    # are not text. Unknown-size Segment extends to its parent's end.
    masters={0x1A45DFA3,0x18538067,0x1549A966,0x1654AE6B,0xAE,0x1254C367,0x7373,0x63C0,0x67C8}
    strings={0x4282,0x4D80,0x5741,0x7BA9,0x45A3,0x4487,0x536E,0x258688,0x86}
    def vint(pos,is_id=False):
        first=data[pos];length=1
        while length<=8 and not first & (1<<(8-length)):length+=1
        if length>8:raise ValueError('Invalid EBML length')
        value=int.from_bytes(data[pos:pos+length],'big')
        if not is_id:value &= (1<<(7*length))-1
        unknown=not is_id and value==(1<<(7*length))-1
        return value,pos+length,unknown
    def walk(start,end):
        pos=start
        while pos<end:
            element,pos,_=vint(pos,True);size,pos,unknown=vint(pos)
            stop=end if unknown else min(pos+size,end)
            if element in masters:walk(pos,stop)
            elif element in strings:inspect_text(name+'!EBML-metadata',data[pos:stop].decode('utf8',errors='replace'),issues)
            if stop<=pos:break
            pos=stop
    walk(0,len(data))


# Only these individually reviewed native deliverables are permitted.
NATIVE_FILES = {
    '模型/循環物流_3D展示.fsm',
    '模型/改善前_現況.fsm',
    '模型/改善後_聯合改善12公尺.fsm',
    '模型/循環物流_實驗完整結果.fsm',
    '模型/歷史V8_實驗完整結果.fsm',
    '模型/歷史V8_實驗完整結果.sqlite',
}

def inspect_binary_text(name, data, issues, skip_email=False):
    for encoding in ('utf8','cp950','latin1','utf-16le','utf-16be'):
        for offset in ((0,1) if encoding.startswith('utf-16') else (0,)):
            found=[]
            inspect_text(name, data[offset:].decode(encoding,errors='replace'), found)
            # IEEE-754 numbers can contain email-shaped bytes. Actual SQLite
            # text cells and schema are checked separately without this exception.
            issues.extend(x for x in found if not (skip_email and x['rule']=='email_address'))

def inspect_native(path, name, data, issues):
    if path.suffix=='.fsm':
        if not data.startswith(b'flexsimtree\x00'):
            issues.append({'file':name,'rule':'invalid_native_header'});return
        try:
            start=data.index(b'\x1f\x8b\x08')
            dec=zlib.decompressobj(16+zlib.MAX_WBITS)
            payload=dec.decompress(data[start:])+dec.flush()
            if not dec.eof or dec.unused_data:
                issues.append({'file':name,'rule':'unparsed_native_trailer'})
            inspect_binary_text(name+'!header',data[:start],issues)
            inspect_binary_text(name+'!decompressed-tree',payload,issues)
        except (ValueError,zlib.error):issues.append({'file':name,'rule':'native_decompression_failed'})
    else:
        inspect_binary_text(name+'!raw-pages',data,issues,skip_email=True)
        with sqlite3.connect(path.resolve().as_uri()+'?mode=ro&immutable=1',uri=True) as db:
            if db.execute('pragma integrity_check').fetchone()[0]!='ok':
                issues.append({'file':name,'rule':'sqlite_integrity'})
            if db.execute('pragma freelist_count').fetchone()[0]!=0:
                issues.append({'file':name,'rule':'sqlite_unused_pages'})
            for table,sql in db.execute("select name,sql from sqlite_master where type='table'").fetchall():
                inspect_text(name+'!schema',sql or '',issues)
                quoted='"'+table.replace('"','""')+'"'
                for row in db.execute('select * from '+quoted):
                    for value in row:
                        if isinstance(value,str):inspect_text(name+'!'+table,value,issues)
                        elif isinstance(value,bytes):inspect_binary_text(name+'!'+table,value,issues)

def main():
    root=Path(__file__).resolve().parents[1]
    issues=[];files=[];size=0
    for p in sorted(root.rglob('*')):
        if not p.is_file() or any(x in SKIP_DIRS for x in p.relative_to(root).parts):continue
        rel=p.relative_to(root).as_posix()
        if p.name=='.env' or (p.suffix.lower() in BLOCKED_SUFFIXES and rel not in NATIVE_FILES):
            issues.append({'file':rel,'rule':'blocked_file_type'})
        if p.suffix.lower() not in ALLOWED_SUFFIXES and p.name not in ALLOWED_BASENAMES and rel not in NATIVE_FILES:
            issues.append({'file':rel,'rule':'unexpected_file_type'})
        b=p.read_bytes();size+=len(b);files.append(rel)
        if len(b)>=100*1024*1024:issues.append({'file':rel,'rule':'github_file_size_limit'})
        if rel in NATIVE_FILES:inspect_native(p,rel,b,issues)
        elif p.suffix=='.pptx':inspect_office(rel,b,issues)
        elif p.suffix in {'.md','.csv','.json','.py'} or p.name in ALLOWED_BASENAMES:
            text=b.decode('utf-8-sig')
            if p.resolve()==Path(__file__).resolve():
                # Inspect the checker too, excluding only its regex definitions.
                node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='RULES' for t in n.targets))
                lines=text.splitlines();text='\n'.join(lines[:node.lineno-1]+lines[node.end_lineno:])
            inspect_text(rel,text,issues)
            if p.suffix=='.json':json.loads(text)
        elif p.suffix in {'.png','.webm'}:
            inspect_media(rel,b,issues)
    manifest=root/'PUBLIC_MANIFEST.json'
    if manifest.exists():
        for row in json.loads(manifest.read_text(encoding='utf8'))['files']:
            p=root/row['path']
            if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=row['sha256']:
                issues.append({'file':row['path'],'rule':'manifest_mismatch'})
    summary={'status':'pass' if not issues else 'fail','files_scanned':len(files),'bytes_scanned':size,'issues':issues,'scope':'allowlisted package, recursive Office XML/workbooks, decompressed native model trees, SQLite schema/text/blob/raw pages; not a universal guarantee'}
    print(json.dumps(summary,ensure_ascii=True,indent=2))
    return 0 if not issues else 1

if __name__=='__main__':sys.exit(main())
