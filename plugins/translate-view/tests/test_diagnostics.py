"""Exercise persisted evidence, not live providers or the user's private configuration."""
import base64
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'scripts'

def module(name):
    path = SCRIPT / (name + '.py')
    spec = importlib.util.spec_from_file_location('test_' + name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'diagnostics'
    def tearDown(self):
        self.tmp.cleanup()
    def store(self):
        self.assertTrue((SCRIPT / 'diagnostics.py').is_file(), 'diagnostic store is not implemented')
        self.d = module('diagnostics')
        return self.d.Store(self.root)
    def test_success_requires_host_confirmation_and_files_are_private(self):
        s = self.store(); h = s.begin({'id': 'a'*32, 'token': 'b'*32, 'managed': True})
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        p = self.root / (h['id']+'.json')
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        s.finish(h['id'], h['token'], 'waiting_host', {'helper': 'success'})
        self.assertTrue(p.exists())
        self.assertFalse(s.control(h['id'], 'c'*32, 'confirm'))
        self.assertTrue(s.control(h['id'], h['token'], 'confirm'))
        self.assertFalse(p.exists())
    def test_failure_survives_late_confirmation_and_retry(self):
        s = self.store(); h = s.begin({}); s.finish(h['id'],h['token'],'failed',{'category':'placeholder'})
        self.assertFalse(s.control(h['id'],h['token'],'confirm'))
        second=s.begin({}); s.control(second['id'],second['token'],'confirm')
        self.assertEqual(s.read(h['id'])['category'],'placeholder')
    def test_expired_writer_cannot_restore_record_and_active_peer_is_untouched(self):
        s = self.store()
        with patch.object(self.d.time,'monotonic',return_value=100): old=s.begin({})
        with patch.object(self.d.time,'monotonic',return_value=1200): live=s.begin({})
        with patch.object(self.d.time,'monotonic',return_value=1301):
            self.assertFalse(s.update(old['id'],old['token'],{'source':'late'}))
            self.assertEqual(s.read(old['id'])['status'],'incomplete')
            self.assertEqual(s.read(live['id'])['status'],'active')
    def test_count_age_and_total_capacity_do_not_evict_active_records(self):
        s=self.store()
        for i in range(22):
            h=s.begin({});s.finish(h['id'],h['token'],'failed',{'category':'test'})
        self.assertEqual(len(list(self.root.glob('*.json'))),20)
        for p in self.root.glob('*.json'):
            data=json.loads(p.read_text());data['createdEpoch']=0;data['finishedEpoch']=0;p.write_text(json.dumps(data))
        h=s.begin({});self.assertEqual(len(list(self.root.glob('*.json'))),1)
        active=[h]+[s.begin({}) for _ in range(5)]
        self.assertTrue(all(active))
        self.assertIsNone(s.begin({}))
        self.assertEqual(len(list(self.root.glob('*.json'))),6)
    def test_symlink_roots_and_record_files_are_rejected(self):
        s=self.store(); h=s.begin({}); p=self.root/(h['id']+'.json');p.unlink()
        victim=Path(self.tmp.name)/'victim';victim.write_text('unchanged');p.symlink_to(victim)
        self.assertIsNone(s.read(h['id']))
        s.clear();self.assertEqual(victim.read_text(),'unchanged')
        linked=Path(self.tmp.name)/'linked';linked.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):self.d.Store(linked).begin({})
    def test_clear_epoch_rejects_prepare_started_before_clear(self):
        s=self.store()
        self.assertTrue(hasattr(s,'epoch'),'clear fencing is not implemented')
        epoch=s.epoch();s.clear()
        self.assertIsNone(s.begin({'id':'a'*32,'token':'b'*32,'epoch':epoch}))
        self.assertIsNotNone(s.begin({'id':'c'*32,'token':'d'*32,'epoch':s.epoch()}))
    def test_just_failed_long_operation_is_retained_by_failure_time(self):
        s=self.store()
        with patch.object(self.d.time,'time',return_value=100):slow=s.begin({})
        for i in range(20):
            with patch.object(self.d.time,'time',return_value=200+i):
                h=s.begin({});s.finish(h['id'],h['token'],'failed',{'category':'short'})
        with patch.object(self.d.time,'time',return_value=300):saved=s.finish(slow['id'],slow['token'],'failed',{'category':'slow'})
        self.assertTrue(saved);self.assertIsNotNone(s.read(slow['id']))
        self.assertEqual(len(list(self.root.glob('*.json'))),20)
    def test_clear_removes_interrupted_atomic_writes_without_touching_other_files(self):
        s=self.store();s.begin({})
        stale=self.root/'.diag-abcd1234';stale.write_text('private interrupted response')
        other=self.root/'my-note.txt';other.write_text('keep')
        s.clear()
        self.assertFalse(stale.exists());self.assertEqual(other.read_text(),'keep')
    def test_parallel_processes_reserve_capacity_without_duplicate_records(self):
        s=self.store()
        code="import importlib.util,json,sys;spec=importlib.util.spec_from_file_location('diag',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);print(json.dumps(m.Store(sys.argv[2]).begin({})))"
        workers=[subprocess.Popen([sys.executable,'-c',code,str(SCRIPT/'diagnostics.py'),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(8)]
        results=[]
        for worker in workers:
            out,error=worker.communicate(timeout=10);self.assertEqual(worker.returncode,0,error);results.append(json.loads(out))
        admitted=[r for r in results if r]
        self.assertEqual(len(admitted),6)
        self.assertEqual(len({r['id'] for r in admitted}),6)
        self.assertEqual(len(list(self.root.glob('*.json'))),6)
    def test_oversize_evidence_is_marked_incomplete_and_clear_prevents_late_writes(self):
        s=self.store();h=s.begin({})
        s.finish(h['id'],h['token'],'failed',{'source':'x'*(self.d.RECORD_LIMIT+1)})
        record=s.read(h['id']);self.assertTrue(record['truncated'])
        self.assertLessEqual((self.root/(h['id']+'.json')).stat().st_size,self.d.RECORD_LIMIT)
        s.clear();self.assertFalse(s.update(h['id'],h['token'],{'source':'resurrect'}))
        self.assertEqual(list(self.root.glob('*.json')),[])

class TranslationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'TRANSLATE_VIEW_CONFIG':self.tmp.name+'/config.json'},clear=True);self.env.start()
        self.m=module('translate')
        self.cfg=dict(self.m.DEFAULTS,enabled=True,detection='script',model='test',baseUrl='https://example.invalid/v1',apiKey='secret-api-value',jevKey='secret-jev-value',diagnosticsMode='failures')
    def tearDown(self):self.env.stop();self.tmp.cleanup()
    def records(self):return list((Path(self.tmp.name)/'diagnostics').glob('*.json'))
    def fake(self, body, content_type='text/event-stream'):
        import io
        class Response(io.BytesIO):
            headers={'Content-Type':content_type}
        return Response(body)
    def broken(self, url,key,body):
        text=body['messages'][-1]['content'];import re
        token=re.search(r'TVKEEP[0-9a-f]+X\d+Z',text)[0]
        text=text.replace(token,'')
        raw='data: '+json.dumps({'choices':[{'delta':{'content':text},'finish_reason':'stop'}]})+'\n\ndata: [DONE]\n\n'
        return self.fake(raw.encode())
    def test_real_sse_validation_failure_saves_exact_request_tokens_and_response(self):
        with patch.object(self.m,'request',self.broken):
            with self.assertRaisesRegex(self.m.TranslationError,'占位符'):self.m.translate(self.cfg,'Please fix `hello()`.', 'outgoing')
        paths=self.records();self.assertEqual(len(paths),1)
        record=json.loads(paths[0].read_text())
        self.assertEqual(record['category'],'placeholder_count')
        self.assertEqual(record['attempts'][0]['tokens'][0]['count'],0)
        self.assertIn('TVKEEP',record['attempts'][0]['request']['messages'][-1]['content'])
        self.assertIn(b'[DONE]',base64.b64decode(record['attempts'][0]['response']['rawBase64']))
        self.assertNotIn('secret-api-value',paths[0].read_text())
    def test_off_is_no_io_and_host_success_waits_for_confirmation(self):
        good=lambda *a:self.fake(b'data: {"choices":[{"delta":{"content":"translated"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')
        with patch.object(self.m,'request',good):
            result=self.m.translate(dict(self.cfg,diagnosticsMode='off'),'Hello.','outgoing')
            self.assertFalse((Path(self.tmp.name)/'diagnostics').exists())
            self.assertNotIn('diagnostic',result)
            result=self.m.translate(self.cfg,'Hello.','outgoing',diagnostic_context={'id':'a'*32,'token':'b'*32,'managed':True})
        self.assertTrue(result['diagnostic']['saved'])
        self.assertEqual(json.loads(self.records()[0].read_text())['status'],'waiting_host')
    def test_split_credentials_are_scrubbed_and_malformed_utf8_is_captured(self):
        raw=b'data: {"choices":[{"delta":{"content":"secret-api-value"}}]}\n'+bytes([255])+b'\n'
        with patch.object(self.m,'request',lambda *a:self.fake(raw)):
            with self.assertRaises(UnicodeError):self.m.translate(self.cfg,'Hello.','outgoing')
        record=json.loads(self.records()[0].read_text());stored=base64.b64decode(record['attempts'][0]['response']['rawBase64'])
        self.assertNotIn(b'secret-api-value',stored);self.assertIn(b'[REDACTED_SECRET]',stored)
        self.assertTrue(record['redacted'])
    def test_failing_store_does_not_replace_translation_error(self):
        with patch.object(self.m,'request',self.broken),patch.object(self.m.diagnostics.Store,'begin',side_effect=OSError('disk')):
            with self.assertRaisesRegex(self.m.TranslationError,'占位符'):self.m.translate(self.cfg,'Please fix `hello()`.', 'outgoing')
        self.assertEqual(self.records(),[])
    def test_offline_replay_uses_failed_response_without_config_or_network(self):
        with patch.object(self.m,'request',self.broken):
            with self.assertRaises(self.m.TranslationError):self.m.translate(self.cfg,'Please fix '+chr(96)+'hello()'+chr(96)+'.','outgoing')
        with patch.object(self.m,'request',side_effect=AssertionError('network forbidden')),patch.object(self.m,'load_config',side_effect=AssertionError('config forbidden')):
            self.assertTrue(hasattr(self.m,'replay_diagnostic'),'offline replay is not implemented')
            result=self.m.replay_diagnostic(self.records()[0])
        self.assertTrue(result['matched'])
        self.assertEqual(result['attempts'][0]['category'],'placeholder_count')
        self.assertNotIn('Please fix',json.dumps(result))
    def test_offline_replay_rejects_untrusted_size_schema_and_encoding(self):
        self.assertTrue(hasattr(self.m,'replay_diagnostic'),'offline replay is not implemented')
        path=Path(self.tmp.name)/'record.json'
        for data in [{'schemaVersion':999,'id':'a'*32},{'schemaVersion':1,'id':'a'*32,'attempts':[{'stage':'translate','response':{'contentType':'text/event-stream','rawBase64':'not base64'}}]}]:
            path.write_text(json.dumps(data))
            with self.assertRaises((ValueError,self.m.TranslationError)):self.m.replay_diagnostic(path)
    def test_helper_control_confirms_clears_and_does_not_create_records_when_off(self):
        self.assertTrue(hasattr(self.m,'diagnostic_control'),'host control is not implemented')
        store=self.m.diagnostic_store();handle=store.begin({'id':'a'*32,'token':'b'*32})
        self.assertTrue(self.m.diagnostic_control(self.cfg,dict(operation='confirm',**handle))['ok'])
        self.assertFalse(self.records())
        result=self.m.diagnostic_control(dict(self.cfg,diagnosticsMode='off'),dict(operation='fail',id='a'*32,token='b'*32,detail={'error':'host'}))
        self.assertFalse(result['ok']);self.assertFalse(self.records())
    def test_cleared_prepared_operation_cannot_recreate_evidence(self):
        store=self.m.diagnostic_store()
        store.begin({'id':'a'*32,'token':'b'*32});store.clear()
        with patch.object(self.m,'request',self.broken):
            with self.assertRaises(self.m.TranslationError):
                self.m.translate(self.cfg,'Please fix '+chr(96)+'hello()'+chr(96)+'.','outgoing',diagnostic_context={'id':'a'*32,'token':'b'*32,'managed':True,'prepared':True})
        self.assertEqual(self.records(),[])
    def test_disabling_capture_cancels_active_but_preserves_existing_failures(self):
        self.m.save_config(self.cfg);store=self.m.diagnostic_store()
        active=store.begin({});failed=store.begin({});store.finish(failed['id'],failed['token'],'failed')
        self.m.save_config({'diagnosticsMode':'off'})
        self.assertIsNone(store.read(active['id']))
        self.assertIsNotNone(store.read(failed['id']))
    def test_valid_json_with_null_choice_replays_as_original_helper_error(self):
        raw=b'data: {"choices":[null]}\n\ndata: [DONE]\n\n'
        with patch.object(self.m,'request',lambda *a:self.fake(raw)):
            with self.assertRaises(AttributeError):self.m.translate(self.cfg,'Hello.','outgoing')
        result=self.m.replay_diagnostic(self.records()[0])
        self.assertTrue(result['matched'])
        self.assertEqual(result['attempts'][0]['category'],'helper_error')
    def test_key_split_across_sse_content_events_is_not_recoverable_from_saved_raw(self):
        parts=['secret-api-','value']
        raw=(''.join('data: '+json.dumps({'choices':[{'delta':{'content':part}}]})+'\n\n' for part in parts)+'data: [DONE]\n\n').encode()
        with patch.object(self.m,'request',lambda *a:self.fake(raw)):
            with self.assertRaises(self.m.TranslationError):self.m.translate(self.cfg,'Please fix '+chr(96)+'hello()'+chr(96)+'.','outgoing')
        record=json.loads(self.records()[0].read_text())
        encoded=record['attempts'][0]['response'].get('rawBase64')
        recovered=''
        if encoded:
            for line in base64.b64decode(encoded).decode().splitlines():
                if line.startswith('data: {'):
                    recovered+=''.join(choice.get('delta',{}).get('content','') for choice in json.loads(line[5:])['choices'])
        self.assertNotIn('secret-api-value',recovered)
        self.assertTrue(record['redacted'])
        self.assertTrue(record['attempts'][0]['response']['bodyOmitted'])
        replay=self.m.replay_diagnostic(self.records()[0])
        self.assertIsNone(replay['matched'])
        self.assertIn('response_omitted_for_redaction',replay['limitations'])
    def test_offline_mapping_cannot_expand_via_recursive_replacement(self):
        path=Path(self.tmp.name)/'malicious.json'
        path.write_text(json.dumps({'schemaVersion':1,'id':'a'*32,'category':'placeholder_count','attempts':[{'stage':'translate','prefix':'','tokens':[{'token':'A','literal':'B'*1000},{'token':'B','literal':'x'*1000}],'response':{'contentType':'application/json','rawBase64':base64.b64encode(b'{"choices":[{"message":{"content":"AB"}}]}').decode()}}]}))
        with self.assertRaises((ValueError,self.m.TranslationError)):self.m.replay_diagnostic(path)
    def test_invalid_config_mode_is_rejected(self):
        with self.assertRaisesRegex(self.m.TranslationError,'诊断'):self.m.validate_config(dict(self.cfg,diagnosticsMode='invalid'))

if __name__=='__main__':unittest.main()
