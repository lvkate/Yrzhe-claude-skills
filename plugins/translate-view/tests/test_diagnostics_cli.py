"""Local HTTP + real helper-process tests; never use a real provider."""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT=Path(__file__).parents[1]/'scripts/translate.py'

class DiagnosticCLI(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.config=self.root/'config.json';self.mode='broken';self.calls=[]
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.calls.append(body)
                if owner.mode=='http':
                    self.send_response(403);self.end_headers();self.wfile.write(b'secret-key-for-test body must not be saved');return
                text=body['messages'][-1]['content']
                if owner.mode=='broken':
                    token=re.search(r'TVKEEP[a-f0-9]+X\d+Z',text)[0]
                    text=text.replace(token,'')+' secret-key-for-test'
                raw='data: '+json.dumps({'choices':[{'delta':{'content':text},'finish_reason':'stop'}]})+'\n\ndata: [DONE]\n\n'
                self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers();self.wfile.write(raw.encode())
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.env=dict(os.environ,TRANSLATE_VIEW_CONFIG=str(self.config),PYTHONDONTWRITEBYTECODE='1')
        self.call({'action':'save','patch':{'enabled':True,'diagnosticsMode':'failures','detection':'script','model':'fixture','apiKey':'secret-key-for-test','baseUrl':f'http://127.0.0.1:{self.server.server_port}/v1'}})
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def call(self,data=None,args=(),env=None):
        result=subprocess.run([sys.executable,str(SCRIPT),*args],input=json.dumps(data) if data is not None else '',capture_output=True,text=True,env=env or self.env,timeout=10)
        self.assertEqual(result.stderr,'')
        return result,[json.loads(x) for x in result.stdout.splitlines()]
    def test_failed_response_replays_offline_and_success_needs_host_ack(self):
        context=dict(id='a'*32,token='b'*32,managed=True,prepared=True,session='fixture',cursor=0,end=21)
        self.assertTrue(self.call(dict(action='diagnostic-control',operation='prepare',**context))[1][0]['ok'])
        result,events=self.call(dict(action='stream',direction='outgoing',text='Please fix '+chr(96)+'hello()'+chr(96)+'.',diagnostic=context))
        self.assertEqual(result.returncode,1);self.assertEqual(events[-1]['type'],'error');self.assertTrue(events[-1]['diagnostic']['saved'])
        path=self.root/'diagnostics'/('a'*32+'.json')
        raw=path.read_text();self.assertNotIn('secret-key-for-test',raw)
        calls=len(self.calls)
        _,replay=self.call(args=['--replay-diagnostic',str(path)],env=dict(self.env,TRANSLATE_VIEW_CONFIG=str(self.root/'not-existing.json')))
        self.assertTrue(replay[0]['reproducedCategory']);self.assertIsNone(replay[0]['matched']);self.assertIn('record_redacted',replay[0]['limitations']);self.assertEqual(len(self.calls),calls)
        self.mode='good';context.update(id='c'*32,token='d'*32)
        self.call(dict(action='diagnostic-control',operation='prepare',**context))
        result,events=self.call(dict(action='translate',direction='outgoing',text='Please fix '+chr(96)+'hello()'+chr(96)+'.',diagnostic=context))
        self.assertEqual(result.returncode,0);success=self.root/'diagnostics'/('c'*32+'.json')
        self.assertEqual(json.loads(success.read_text())['status'],'waiting_host')
        self.assertTrue(self.call(dict(action='diagnostic-control',operation='confirm',**context))[1][0]['ok'])
        self.assertFalse(success.exists());self.assertTrue(path.exists())
    def test_http_error_body_is_never_saved_and_clear_is_local(self):
        self.mode='http'
        result,events=self.call(dict(action='translate',direction='outgoing',text='Hello.'))
        self.assertEqual(result.returncode,1)
        paths=list((self.root/'diagnostics').glob('*.json'));self.assertEqual(len(paths),1)
        record=json.loads(paths[0].read_text())
        self.assertEqual(record['category'],'http');self.assertEqual(record['attempts'][0]['httpCode'],403)
        self.assertNotIn('body must not be saved',paths[0].read_text());self.assertNotIn('response',record['attempts'][0])
        before=len(self.calls);self.call(dict(action='diagnostic-control',operation='clear'))
        self.assertEqual(len(self.calls),before);self.assertEqual(list((self.root/'diagnostics').glob('*.json')),[])

if __name__=='__main__':unittest.main()
