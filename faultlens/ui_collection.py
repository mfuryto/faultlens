"""Cancellable bounded CLI collection for the terminal workspace; no shell or elevation."""
import asyncio
import json
import os
from pathlib import Path
import signal
import sys

MAX_OUTPUT=8*1024*1024


def arguments(page,settings):
    commands=('status','health','network','security','incidents','diagnose')
    if type(page) is not int or not 0<=page<len(commands): raise ValueError('Not a source page')
    args=[commands[page],'--json']
    if page==5 and settings.investigation_mode:
        args=['investigate','--json','--mode',settings.investigation_mode]
    if page in {0,1,2,3}: args+=['--sample-seconds',str(settings.sample_seconds)]
    if page==1 and settings.preservation: args+=['--history']
    if page in {2,3} and settings.sockets: args+=['--sockets']
    if page in {4,5} and settings.system_journal: args+=['--system-journal']
    if page==4:
        args+=['--boot-count',str(settings.boot_count)]
        if settings.include_current: args+=['--include-current']
    if page==5:
        if not settings.investigation_mode and not settings.boot_selector: raise ValueError('Technical reader requires a boot selector')
        if settings.boot_selector:
            args+=['--boot-id' if len(settings.boot_selector)==32 else '--boot',settings.boot_selector]
        if not settings.investigation_mode: args+=['--show-evidence']
        else: args+=['--sample-seconds',str(settings.sample_seconds)]
        if settings.investigation_mode=='now' and settings.sockets: args+=['--sockets']
        if settings.investigation_mode and not settings.search_events: args+=['--no-search-events']
        for key,flag in (('search_events','--search-events'),('search_ssh','--search-ssh'),
                         ('search_firewall','--search-firewall'),('pstore','--pstore'),('pstore_archive','--pstore-archive')):
            if getattr(settings,key): args.append(flag)
        if settings.atop_date:
            args+=['--atop-date',settings.atop_date]
            if settings.atop_extended: args+=['--atop-extended']
        for key,flag in (('since_us','--since-us'),('until_us','--until-us')):
            if getattr(settings,key) and (not settings.investigation_mode or settings.investigation_mode=='period'): args+=[flag,getattr(settings,key)]
    return args


async def stop(process):
    if process.returncode is not None: return
    try: os.killpg(process.pid,signal.SIGINT)
    except ProcessLookupError: return
    try: await asyncio.wait_for(process.wait(),2)
    except asyncio.TimeoutError:
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        await process.wait()


async def bounded_read(stream,limit):
    data=bytearray()
    while True:
        chunk=await stream.read(min(65536,limit-len(data)+1))
        if not chunk: return bytes(data)
        data.extend(chunk)
        if len(data)>limit: raise ValueError('Collection output limit')


async def collect(page,settings):
    args=arguments(page,settings)
    launcher=Path(__file__).resolve().parents[1]/'bin'/'faultlens'
    process=await asyncio.create_subprocess_exec(sys.executable,'-I','-B',str(launcher),*args,
        stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
        cwd='/',start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C',
                                         'PYTHONDONTWRITEBYTECODE':'1','NO_COLOR':'1'})
    tasks=[asyncio.create_task(bounded_read(process.stdout,MAX_OUTPUT)),
           asyncio.create_task(bounded_read(process.stderr,131072))]
    try:
        async with asyncio.timeout(60):
            output,_=await asyncio.gather(*tasks)
            code=await process.wait()
        if code!=0: raise ValueError('Collection unsuccessful')
        value=json.loads(output.decode('utf-8'),parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite output')))
        if not isinstance(value,dict) or value.get('schema_version')!=1 or value.get('command')!=args[0]:
            raise ValueError('Invalid collection report')
        return value
    finally:
        # Let native command finally blocks clean up their child groups before force.
        await stop(process)
        for task in tasks:
            if not task.done(): task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
