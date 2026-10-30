"""Private, bounded diagnostic evidence. This module never performs network requests."""
import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import time
import threading
import uuid
from pathlib import Path

RECORD_LIMIT = 8 * 1024 * 1024
TOTAL_LIMIT = 50 * 1024 * 1024
MAX_RECORDS = 20
MAX_AGE = 7 * 24 * 60 * 60
LEASE = 1200
ACTIVE = ('active', 'waiting_host')
IDENTIFIER = re.compile(r'[a-f0-9]{32}\Z')

def identity(value):
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))

def stamp():
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + f'.{int(time.time()*1000)%1000:03d}Z'

def decode_record(path):
    """Read an untrusted self-contained record without following links or external references."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise ValueError('不是普通诊断文件。')
        raw = f.read(RECORD_LIMIT + 1)
    if len(raw) > RECORD_LIMIT: raise ValueError('诊断文件超过 8 MiB。')
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get('schemaVersion') != 1 or not identity(data.get('id')):
        raise ValueError('不支持的诊断记录。')
    if not isinstance(data.get('attempts', []), list): raise ValueError('诊断请求格式错误。')
    return data

class Store:
    """Serialize all mutations and account for active reservations before admitting a writer."""
    def __init__(self, root):
        self.root = Path(root)
    @contextlib.contextmanager
    def locked(self):
        if self.root.is_symlink(): raise OSError('诊断目录不能是符号链接。')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info=self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid(): raise OSError('诊断目录所有者不符。')
        self.root.chmod(0o700)
        fd=os.open(self.root/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode): raise OSError('诊断锁不是普通文件。')
            os.fchmod(fd,0o600);fcntl.flock(fd,fcntl.LOCK_EX)
            # Atomic writers hold this same lock, so only interrupted writes
            # can remain here after another process acquires it.
            for path in self.root.iterdir():
                if re.fullmatch(r'\.(?:diag|epoch)-[a-z0-9_]{8}',path.name):
                    info=path.lstat()
                    if stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid():path.unlink()
            yield
        finally:
            os.close(fd)
    def epoch(self):
        try:
            fd=os.open(self.root/'.epoch',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:return '0'
        with os.fdopen(fd,'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):raise ValueError('无效清除代次。')
            value=stream.read(65).decode('ascii')
        if not identity(value):raise ValueError('无效清除代次。')
        return value
    def advance_epoch(self):
        fd,tmp=tempfile.mkstemp(dir=self.root,prefix='.epoch-')
        try:
            with os.fdopen(fd,'w') as stream:
                stream.write(uuid.uuid4().hex);stream.flush();os.fsync(stream.fileno())
            os.replace(tmp,self.root/'.epoch')
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    def path(self, identifier):
        if not identity(identifier): raise ValueError('无效诊断编号。')
        return self.root/(identifier+'.json')
    def read(self, identifier):
        try: return decode_record(self.path(identifier))
        except (OSError, ValueError, TypeError, RecursionError): return None
    def write(self, record):
        raw=json.dumps(record,ensure_ascii=False,separators=(',',':')).encode()
        if len(raw)>RECORD_LIMIT:
            record={k:v for k,v in record.items() if k in ('schemaVersion','id','ownerHash','created','createdEpoch','updated','lease','status','category','error')}
            record.update(truncated=True,attempts=[],limitations=['record_size_limit'])
            raw=json.dumps(record,ensure_ascii=False).encode()
            if len(raw)>RECORD_LIMIT: raise ValueError('诊断元数据超过上限。')
        fd,tmp=tempfile.mkstemp(dir=self.root,prefix='.diag-')
        try:
            with os.fdopen(fd,'wb') as out:
                out.write(raw);out.flush();os.fsync(out.fileno())
            os.replace(tmp,self.path(record['id']))
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    def records(self):
        return [(p,r) for p in self.root.glob('*.json') if identity(p.stem) and (r:=self.read(p.stem)) is not None and r['id']==p.stem]
    def cleanup(self, reserve=0):
        now=time.monotonic(); records=self.records()
        for p,r in records:
            if r.get('status') in ACTIVE and (now>r.get('lease',0) or r.get('lease',0)>now+LEASE+1):
                r.update(status='incomplete',category='lease_expired',finishedEpoch=time.time());self.write(r)
        active=[(p,r) for p,r in records if r.get('status') in ACTIVE]
        ended=sorted([(p,r) for p,r in records if r.get('status') not in ACTIVE],key=lambda x:x[1].get('finishedEpoch',x[1].get('createdEpoch',0)))
        # Each active operation reserves its maximum possible serialized size.
        used=len(active)*RECORD_LIMIT+sum(p.stat().st_size for p,_ in ended)
        while ended:
            p,r=ended[0]
            if len(ended)<=MAX_RECORDS and time.time()-r.get('finishedEpoch',r.get('createdEpoch',0))<=MAX_AGE and used+reserve<=TOTAL_LIMIT:break
            used-=p.stat().st_size;p.unlink();ended.pop(0)
        return used+reserve<=TOTAL_LIMIT
    def begin(self, context):
        context=dict(context)
        context.setdefault('epoch',self.epoch())
        identifier=context.get('id') or uuid.uuid4().hex;token=context.get('token') or uuid.uuid4().hex
        if not identity(identifier) or not identity(token):raise ValueError('无效操作身份。')
        with self.locked():
            if context['epoch']!=self.epoch():return None
            if not self.cleanup(RECORD_LIMIT) or self.path(identifier).exists() or self.path(identifier).is_symlink():return None
            record=dict(schemaVersion=1,id=identifier,ownerHash=hashlib.sha256(token.encode()).hexdigest(),created=stamp(),createdEpoch=time.time(),lease=time.monotonic()+LEASE,status='active',attempts=[],context={k:v for k,v in context.items() if k not in ('token','id')})
            self.write(record)
        return dict(id=identifier,token=token)
    def owned(self, identifier, token):
        record=self.read(identifier)
        return record if record and identity(token) and hmac.compare_digest(record.get('ownerHash',''),hashlib.sha256(token.encode()).hexdigest()) else None
    def update(self, identifier, token, patch):
        with self.locked():
            self.cleanup();r=self.owned(identifier,token)
            if not r or r.get('status') not in ACTIVE:return False
            r.update({k:v for k,v in patch.items() if k not in ('id','ownerHash','created','createdEpoch','schemaVersion','status','lease')})
            r.update(lease=time.monotonic()+LEASE,updated=stamp());self.write(r);return True
    def finish(self, identifier, token, status, patch=None):
        if status not in ('failed','waiting_host'):raise ValueError('无效结束状态。')
        with self.locked():
            self.cleanup();r=self.owned(identifier,token)
            if not r or r.get('status') not in ACTIVE:return False
            r.update(patch or {});r.update(status=status,updated=stamp(),lease=time.monotonic()+LEASE)
            if status=='failed':r['finishedEpoch']=time.time()
            self.write(r);self.cleanup();return self.read(identifier) is not None
    def control(self, identifier, token, action, patch=None):
        with self.locked():
            self.cleanup();r=self.owned(identifier,token)
            if not r:return False
            active=r.get('status') in ACTIVE
            if action in ('confirm','cancel'):
                if not active:return False
                self.path(identifier).unlink();return True
            if action=='touch':
                if not active:return False
                r['lease']=time.monotonic()+LEASE
            elif action=='fail':
                if not active and r.get('status')!='failed':return False
                if active:r['finishedEpoch']=time.time()
                r.update(status='failed',host=patch or {})
                if 'category' not in r:r['category']='host_output'
            else:return False
            self.write(r);self.cleanup();return True
    def cancel_active(self):
        with self.locked():
            for path,record in self.records():
                if record.get('status') in ACTIVE:path.unlink()
    def clear(self):
        with self.locked():
            self.advance_epoch()
            count=0
            for p,r in self.records():p.unlink();count+=1
            return count

class Capture:
    """Observe one helper operation; keep credentials only in memory for redaction."""
    def __init__(self, store, context, secrets=()):
        self.store=store;self.secrets=sorted({s for s in secrets if s},key=len,reverse=True)
        self.handle=None;self.saved=False;self.truncated=False;self.redacted=False
        self.data=dict(attempts=[],events=[],context={})
        self.started=time.monotonic();self.last_touch=self.started
        self.stop=threading.Event()
        try:
            context=dict(context)
            context.setdefault('epoch',store.epoch())
            clean=self.clean(context)
            self.data['context']={k:v for k,v in clean.items() if k not in ('id','token')}
            existing=store.owned(clean.get('id'),clean.get('token')) if identity(clean.get('id')) else None
            self.handle=dict(id=clean['id'],token=clean['token']) if existing and existing.get('status') in ACTIVE else None if clean.get('prepared') else store.begin(clean)
        except (OSError,ValueError,TypeError,RecursionError):pass
        if self.handle:
            def renew():
                while not self.stop.wait(30):
                    try:
                        if not self.store.control(self.handle['id'],self.handle['token'],'touch'):break
                    except (OSError,ValueError):break
            threading.Thread(target=renew,daemon=True).start()
    def clean(self, value):
        if isinstance(value,str):
            for secret in self.secrets:
                if secret in value:self.redacted=True;value=value.replace(secret,'[REDACTED_SECRET]')
            return value
        if isinstance(value,dict):return {self.clean(k):self.clean(v) for k,v in value.items()}
        if isinstance(value,list):return [self.clean(v) for v in value]
        return value
    def snapshot(self):
        data=self.clean(dict(self.data,truncated=self.truncated))
        data['redacted']=self.redacted
        return data
    def sync(self):
        if not self.handle:return False
        try:
            self.saved=self.store.update(self.handle['id'],self.handle['token'],patch=self.snapshot())
            return self.saved
        except (OSError,ValueError,TypeError,RecursionError):self.saved=False;return False
    def finish(self, status, **fields):
        self.stop.set()
        self.data.update(fields)
        if not self.handle:return False
        try:
            self.saved=self.store.finish(self.handle['id'],self.handle['token'],status=status,patch=self.snapshot())
            return self.saved
        except (OSError,ValueError,TypeError,RecursionError):self.saved=False;return False
    def discard(self):
        self.stop.set()
        if not self.handle:return
        try:self.store.control(self.handle['id'],self.handle['token'],'confirm')
        except (OSError,ValueError):pass
    def body(self, raw):
        for secret in self.secrets:
            keys={secret.encode(),json.dumps(secret,ensure_ascii=False)[1:-1].encode(),json.dumps(secret,ensure_ascii=True)[1:-1].encode()}
            for key in keys:
                if key in raw:self.redacted=True;raw=raw.replace(key,b'[REDACTED_SECRET]')
        # Content events can reconstruct a key despite intervening SSE framing.
        # Omit those frames when in-place byte redaction cannot remove the key.
        choices={}
        for line in raw.splitlines():
            if not line.startswith(b'data:'):continue
            try:data=json.loads(line[5:].strip())
            except (ValueError,UnicodeError):continue
            if not isinstance(data,dict):continue
            for choice in data.get('choices',[]) if isinstance(data.get('choices',[]),list) else []:
                if not isinstance(choice,dict):continue
                delta=choice.get('delta',{})
                content=delta.get('content') if isinstance(delta,dict) else None
                if isinstance(content,str):
                    index=str(choice.get('index',0))
                    choices.setdefault(index,[]).append(content)
        if any(secret in text for secret in self.secrets for parts in choices.values() for text in [''.join(parts)]):
            self.redacted=True
            return None
        return base64.b64encode(raw).decode('ascii')
    def summary(self):
        return dict(id=self.handle['id'] if self.handle else '',saved=self.saved,enabled=True)

class ObservedResponse:
    """Keep bounded bytes in memory until a read/close boundary, then redact as one body."""
    def __init__(self, response, capture, attempt, limit):
        self.response=response;self.headers=response.headers;self.capture=capture;self.attempt=attempt
        self.limit=limit;self.raw=bytearray();self.arrivals=[];self.start=time.monotonic()
    def observed(self, chunk):
        if len(self.raw)<self.limit:self.raw.extend(chunk[:self.limit-len(self.raw)])
        if len(self.arrivals)<10000:self.arrivals.append(dict(offset=len(self.raw),ms=round((time.monotonic()-self.start)*1000,3)))
        else:self.capture.truncated=True
        return chunk
    def save(self):
        content_type=self.headers.get('Content-Type','')
        self.attempt['response']=dict(contentType=content_type,rawBase64=self.capture.body(bytes(self.raw)),arrivals=self.arrivals)
        if self.attempt['response']['rawBase64'] is None:self.attempt['response']['bodyOmitted']=True
        self.attempt['response']['requestId']=next((self.headers.get(k) for k in ('x-request-id','request-id','x-goog-request-id') if self.headers.get(k)),None)
        self.capture.sync()
    def read(self, size=-1):
        try:return self.observed(self.response.read(size))
        finally:self.save()
    def __iter__(self):
        try:
            for chunk in self.response:yield self.observed(chunk)
        finally:self.save()
    def __enter__(self):return self
    def __exit__(self,*args):
        self.save();self.response.close()
