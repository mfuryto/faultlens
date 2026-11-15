"""Summarize repository tests and read-only native Faultlens server checks."""
from pathlib import Path
import argparse
import json
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from faultlens.cli import SafeArgumentParser, atop_date, boot_index
from faultlens.server_check import WORKERS, check_server, exit_code, run_worker


def terminal_text(value):
    return json.dumps(value,ensure_ascii=True)[1:-1]


def main(argv=None):
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--json',action='store_true',help='Emit the structured summary to stdout only.')
    parser.add_argument('--live-only',action='store_true',help='Skip repository tests; still use current access rights without elevation.')
    parser.add_argument('--boot',type=boot_index,default=0,help='Visible boot index to diagnose; default 0.')
    parser.add_argument('--atop-date',type=atop_date,help='Explicit optional YYYYMMDD recording replay, including extended samples.')
    parser.add_argument('--pstore',action='store_true',help='Explicitly test both fixed live/archive pstore readers.')
    parser.add_argument('--details',action='store_true',help='Include bounded escaped excerpts from failed repository tests.')
    parser.add_argument('--worker',choices=WORKERS,help=argparse.SUPPRESS)
    args=parser.parse_args(argv)
    if sys.platform!='linux':
        parser.error('Linux is required.')
    try:
        if args.worker:
            run_worker(args.worker,boot=args.boot,atop_date=args.atop_date,pstore=args.pstore)
            return 0
        progress=None if args.json else lambda name: print('Running '+name+'...',file=sys.stderr,flush=True)
        data=check_server(live_only=args.live_only,boot=args.boot,atop_date=args.atop_date,
                          pstore=args.pstore,details=args.details,progress=progress)
        if args.json:
            print(json.dumps(data,ensure_ascii=True,allow_nan=False))
        else:
            print('Faultlens read-only server checks: '+data['overall'])
            print('PASS=check worked | WARN=attention | MISSING=evidence unavailable | SKIP=not tested | FAIL=check failed')
            for item in data['checks']:
                print('['+item['state']+'] '+terminal_text(item['key'])+': '+terminal_text(item['message']))
                if item['advice']: print('  '+terminal_text(item['advice']))
                if 'details' in item:
                    print('  Failure excerpt (escaped; truncated='+str(item['details_truncated'])+'): '+json.dumps(item['details'],ensure_ascii=True))
            print('Summary: '+' | '.join(key+'='+str(value) for key,value in data['counts'].items()))
            for text in data['limitations']: print('Note: '+text)
        return exit_code(data)
    except BrokenPipeError:
        return 0
    except OSError:
        print('Server checks could not initialize; no configuration changes attempted.',file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Server checks interrupted; no configuration changes attempted.',file=sys.stderr)
        return 130


if __name__=='__main__':
    raise SystemExit(main())
