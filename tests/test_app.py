import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from sentinel.app import create_app

@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / 'test.sqlite3'), headers={'X-Sentinel':'local'}) as c:
        yield c

def case(c, scope='self-audit'):
    r=c.post('/api/cases',json={'title':'Synthetic audit','purpose':'Test authorized public research','scope':scope})
    assert r.status_code==201
    return r.json()['id']

def evidence(c,cid,**changes):
    item={'title':'Synthetic publication','source':'https://example.org/paper','notes':'Public research excerpt','event_date':'2026-01-02','status':'unverified','rationale':''}
    item.update(changes)
    return c.post(f'/api/cases/{cid}/evidence',json=item)

def test_case_evidence_report_and_delete(client):
    cid=case(client)
    r=evidence(client,cid)
    assert r.status_code==201
    report=client.get(f'/api/cases/{cid}/report').json()
    record=report['evidence'][0]
    payload={k:record[k] for k in ('title','source','notes','event_date','status','rationale')}
    assert record['sha256']==hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
    assert client.delete(f'/api/cases/{cid}').status_code==200
    assert client.get(f'/api/cases/{cid}').status_code==404

def test_persistence(tmp_path):
    path=tmp_path/'persist.sqlite3'
    with TestClient(create_app(path),headers={'X-Sentinel':'local'}) as c:
        cid=case(c)
    with TestClient(create_app(path)) as c:
        assert c.get(f'/api/cases/{cid}').json()['case']['title']=='Synthetic audit'

@pytest.mark.parametrize('source',['javascript:alert(1)','file:///etc/passwd','https://user:password@example.org'])
def test_unsafe_citations(client,source):
    assert evidence(client,case(client),source=source).status_code==422

def test_verification_requires_rationale(client):
    cid=case(client)
    assert evidence(client,cid,status='verified').status_code==422
    assert evidence(client,cid,status='verified',rationale='Direct source reviewed on publication site').status_code==201
    assert evidence(client,cid,event_date='2026-02-30').status_code==422

def test_relationship_is_case_bound(client):
    a,b=case(client),case(client)
    e1=evidence(client,a).json()['id']; e2=evidence(client,b).json()['id']
    data={'source_id':e1,'target_id':e2,'label':'cites','rationale':'Explicit citation in source'}
    assert client.post(f'/api/cases/{a}/links',json=data).status_code==422
    data['target_id']=evidence(client,a,title='Second source').json()['id']
    assert client.post(f'/api/cases/{a}/links',json=data).status_code==201
    assert len(client.get(f'/api/cases/{a}/report').json()['links'])==1

def test_security_boundary(client):
    assert client.get('/',headers={'Host':'evil.example'}).status_code==400
    assert client.get('/api/cases',headers={'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/cases',headers={'X-Sentinel':''},json={}).status_code==403
    r=client.get('/')
    assert r.status_code==200
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']
    assert r.headers['cache-control']=='no-store'

def test_research_scope_and_validation(client):
    cid=case(client,'public-research')
    base={'kind':'username','query':'example','consent':True}
    assert client.post(f'/api/cases/{cid}/research',json=base).status_code==403
    base.update(kind='domain',query='127.0.0.1')
    assert client.post(f'/api/cases/{cid}/research',json=base).status_code==422
    base['query']='example.org';base['consent']=False
    assert client.post(f'/api/cases/{cid}/research',json=base).status_code==422
    base['consent']=True
    r=client.post(f'/api/cases/{cid}/research',json=base)
    assert len(r.json()['leads'])==3
    assert client.get('/api/email-check').json()['url']=='https://haveibeenpwned.com/'

def test_username_provider_outcomes(client,monkeypatch):
    import httpx
    cid=case(client)
    async def found(self,url,**kwargs):
        return httpx.Response(200,json={'email':'must-not-collect@example.org'},request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx.AsyncClient,'get',found)
    data={'kind':'username','query':'example','consent':True}
    r=client.post(f'/api/cases/{cid}/research',json=data)
    assert r.status_code==200
    assert 'must-not-collect' not in r.text
    assert r.json()['findings'][0]['status']=='unverified'
    async def missing(self,url,**kwargs):
        return httpx.Response(404,request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx.AsyncClient,'get',missing)
    assert client.post(f'/api/cases/{cid}/research',json=data).json()['findings']==[]
    async def limited(self,url,**kwargs):
        return httpx.Response(429,request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx.AsyncClient,'get',limited)
    assert client.post(f'/api/cases/{cid}/research',json=data).status_code==502
