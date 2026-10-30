#!/usr/bin/env python3
"""Isolated real Claude PTY diagnostic smoke; synthetic prompts and local HTTP only."""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from terminal_smoke import Harness, PLUGIN

def main():
    root=Path(tempfile.mkdtemp(prefix='translate-diagnostics-pty-'))
    print('Artifacts:',root,flush=True)
    h=Harness(root,columns=180,rows=55)
    config=root/'config.json';records=root/'diagnostics'
    try:
        h.wait(lambda:'Translation' in h.view(),'translation pane loaded')
        cfg=json.loads(config.read_text());cfg.update(diagnosticsMode='failures',detection='script');config.write_text(json.dumps(cfg))
        h.send('请解释测试功能。\r')
        h.wait(lambda:'这是译文。' in h.view() and '翻译中' not in h.view(),'normal translation completed')
        h.wait(lambda:records.exists() and not list(records.glob('*.json')),'host confirmed success removes temporary evidence')
        h.click('设置')
        h.wait(lambda:'失败诊断:' in h.view(),'diagnostic setting visible in real terminal')
        h.wait(lambda:'本机保存失败正文' in h.view(),'saved diagnostic opt-in displayed')
        h.click('取消')
        def damaged_response(handler):
            body=json.loads(handler.rfile.read(int(handler.headers['Content-Length'])))
            h.requests.append(body)
            incoming='English' in body['messages'][0]['content']
            text='Please explain this feature.' if incoming else body['messages'][-1]['content']
            if not incoming:
                token=re.search(r'TVKEEP[0-9a-f]+X\d+Z',text)
                assert token,'fixture answer should contain protected code'
                text=text.replace(token[0],'',1)
            raw='data: '+json.dumps({'choices':[{'delta':{'content':text},'finish_reason':'stop'}]})+'\n\ndata: [DONE]\n\n'
            handler.send_response(200);handler.send_header('Content-Type','text/event-stream');handler.end_headers();handler.wfile.write(raw.encode())
        h.server.RequestHandlerClass.do_POST=damaged_response
        h.send('请再次解释测试功能。\r')
        h.wait(lambda:'翻译失败' in h.view() and '诊断编号' in h.view(),'placeholder failure shows diagnostic identity')
        paths=list(records.glob('*.json'));assert len(paths)==1,paths
        record=json.loads(paths[0].read_text())
        assert record['category']=='placeholder_count',record.get('category')
        assert record['context']['direction']=='outgoing'
        assert record['attempts'][0]['tokens'][0]['count']==0
        assert 'fixture-secret' not in paths[0].read_text()
        copy=root/'failed-evidence.json';copy.write_text(paths[0].read_text());copy.chmod(0o600)
        replay=subprocess.run([sys.executable,str(PLUGIN/'scripts/translate.py'),'--replay-diagnostic',str(copy)],capture_output=True,text=True,timeout=10)
        assert replay.returncode==0,replay.stderr
        result=json.loads(replay.stdout);assert result['matched'] is True,result
        (root/'replay.json').write_text(replay.stdout)
        h.click('设置')
        h.wait(lambda:'清除本机诊断记录' in h.view(),'clear control visible')
        h.click('清除本机诊断记录')
        h.wait(lambda:'已清除本机诊断记录' in h.view() and not list(records.glob('*.json')),'clear removes stored failure locally')
        (root/'verification.json').write_text(json.dumps({'success_ack':True,'failure_record':True,'offline_replay':True,'clear_ui':True},indent=2))
        print('Diagnostic terminal smoke completed.',flush=True)
    finally:h.close()

if __name__=='__main__':main()
