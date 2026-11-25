"""Bounded public-source adapters; never fetch arbitrary user-supplied URLs."""
import asyncio
from datetime import datetime, timezone
from urllib.parse import quote
import httpx

async def collect(kind, query):
    checked = datetime.now(timezone.utc).isoformat()
    findings, sources = [], []
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, headers={'User-Agent':'Sentinel-Local-Research/1.0'}) as client:
        async def fetch(provider, url, params=None):
            try:
                response = await client.get(url, params=params)
                if response.status_code in (401, 403):
                    return None, {'provider':provider,'availability':'access restricted','checked':checked}
                response.raise_for_status()
                return response.json(), {'provider':provider,'availability':'publicly accessible','checked':checked}
            except (httpx.HTTPError, ValueError):
                return None, {'provider':provider,'availability':'availability unconfirmed','checked':checked}
        if kind == 'domain':
            records = ('A', 'AAAA', 'MX', 'NS', 'CAA')
            results = await asyncio.gather(*(fetch('Google DNS · '+record,'https://dns.google/resolve',{'name':query,'type':record}) for record in records))
            for record, (data, source) in zip(records, results):
                sources.append(source)
                if not isinstance(data, dict):
                    continue
                if data.get('Status') not in (0, 3):
                    source['availability']='availability unconfirmed'
                    continue
                for answer in data.get('Answer', [])[:20]:
                    findings.append({'title':f'{query} · {record} DNS record','source':f'https://dns.google/resolve?name={quote(query)}&type={record}',
                        'notes':f"Record owner: {answer.get('name', '')}\nRecord type: {answer.get('type', '')}\nValue: {answer.get('data', '')}\nTTL: {answer.get('TTL', '')}",
                        'status':'unverified','availability':source['availability'],'checked':checked})
        else:
            parameter = 'query.author' if kind == 'professional' else 'query.bibliographic'
            data, source = await fetch('Crossref publications','https://api.crossref.org/works',{parameter:query,'rows':10})
            sources.append(source)
            if isinstance(data,dict) and isinstance(data.get('message'),dict):
                for item in data['message'].get('items',[])[:10]:
                    doi = item.get('DOI')
                    if not doi:
                        continue
                    title = (item.get('title') or ['Untitled publication'])[0]
                    findings.append({'title':str(title)[:250],'source':'https://doi.org/'+quote(str(doi),safe='/'),
                        'notes':f"Publisher: {item.get('publisher', 'Unknown')}\nType: {item.get('type', 'Unknown')}\nDOI: {doi}\nSearch candidate only. A name match does not establish identity. Public metadata does not imply public full text.",
                        'status':'unverified','availability':source['availability'],'checked':checked})
    return {'findings':findings,'sources':sources,'message':f'{len(findings)} findings collected. Availability describes the queried endpoint, not linked full text.'}
