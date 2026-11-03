"""Hourly, checksum-verified inventory of bundled LTS 20 VFS descriptors."""
import asyncio
import hashlib
import io
import json
import re
import time
import zipfile
from .cache import RETENTION

FEED = 'https://s3.amazonaws.com/help-deepsecurity-trendmicro/Resources/CustomScripts/download-center/data/ds-dlc-feed-src/en-us/products_lts.json'
STREAMS = {**{f'rhel{v}': f'RedHat_EL{v}' for v in (8,9,10)}, **{f'debian{v}': f'Debian_{v}' for v in (12,13)}, **{f'sles{v}': f'SuSE_{v}' for v in (15,16)}, **{f'ubuntu{v}': f'Ubuntu_{v[:2]}.{v[2:]}' for v in ('2004','2204','2404','2604')}}


def inspect_archive(data, card):
    if hashlib.sha256(data).hexdigest() != card['sha256'].lower():
        raise ValueError('Agent checksum mismatch')
    prefix = 'Plugin-VFS_Filter_'
    suffix = f"-{card['platform']}-{card['release']}."
    entries = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            if name.startswith(prefix) and suffix in name and name.endswith('.dsp'):
                entries.append(name[len(prefix):name.index(suffix)])
    return sorted(set(entries))


class Inventory:
    def __init__(self, cache, client, clock=time.time):
        self.cache, self.client, self.clock = cache, client, clock
        self.lock = asyncio.Lock()
        self.attempted = 0
        self.error = None
        cache.db.execute('CREATE TABLE IF NOT EXISTS agents (filename TEXT PRIMARY KEY, product TEXT, payload TEXT, seen REAL)')
        cache.db.commit()

    async def tick(self):
        if self.lock.locked() or self.clock()-self.attempted < 3600:
            return
        async with self.lock:
            self.attempted = self.clock()
            try:
                response = await self.client.get(FEED)
                response.raise_for_status()
                cards = [c for g in response.json() if g.get('name') == 'Agent' for c in g['cards'] if c.get('majorMinor') == '20.0' and not c.get('disabled') and c.get('platform') in STREAMS.values()]
                # Start with the latest release for each OS/architecture stream; retain
                # previously observed releases for ten days after supersession.
                latest = {}
                for card in cards:
                    arch = card['filename'].split('.')[-2]
                    key = (card['platform'], arch)
                    if key not in latest or card['releaseTimestamp'] > latest[key]['releaseTimestamp']:
                        latest[key] = card
                for card in latest.values():
                    filename = card['filename']
                    product = next(p for p, stream in STREAMS.items() if stream == card['platform'])
                    existing = self.cache.db.execute('SELECT payload FROM agents WHERE filename=?', (filename,)).fetchone()
                    if existing:
                        with self.cache.db:
                            self.cache.db.execute('UPDATE agents SET seen=? WHERE filename=?', (self.clock(), filename))
                        continue
                    url = card['download']
                    if not url.startswith('https://files.trendmicro.com/products/deepsecurity/en/20.0/') or not filename.endswith('.zip'):
                        continue
                    data = bytearray()
                    async with self.client.stream('GET', url, timeout=180, follow_redirects=False) as download:
                        download.raise_for_status()
                        async for chunk in download.aiter_bytes():
                            data.extend(chunk)
                            if len(data) > 300*1024*1024:
                                raise ValueError('Agent exceeds download limit')
                    kernels = await asyncio.to_thread(inspect_archive, data, card)
                    payload = {k: card.get(k) for k in ('filename','release','platform','download','sha256','releaseDate')}
                    payload.update(kernels=kernels, checked=int(self.clock()*1000), architecture=filename.split('.')[-2])
                    with self.cache.db:
                        self.cache.db.execute('INSERT OR REPLACE INTO agents VALUES (?,?,?,?)', (filename, product, json.dumps(payload), self.clock()))
                self.error = None
            except Exception as error:
                self.error = str(error)
            finally:
                with self.cache.db:
                    self.cache.db.execute('DELETE FROM agents WHERE seen <= ?', (self.clock()-RETENTION,))

    def snapshot(self):
        rows = self.cache.db.execute('SELECT product,payload FROM agents WHERE seen > ? ORDER BY seen DESC', (self.clock()-RETENTION,))
        result = {}
        for row in rows:
            result.setdefault(row['product'], []).append(json.loads(row['payload']))
        return {'products': result, 'error': self.error, 'attempted': int(self.attempted*1000), 'source': FEED}

    async def worker(self):
        while True:
            await self.tick()
            await asyncio.sleep(60)
