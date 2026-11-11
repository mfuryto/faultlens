"""Opt-in read-only comparison with trusted local free/df and Linux interfaces."""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from faultlens.validation import exit_code, validate
from faultlens.cli import SafeArgumentParser


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='Emit comparison states only; no raw host values.')
    args = parser.parse_args()
    if sys.platform != 'linux':
        print('Linux is required.', file=sys.stderr)
        return 2
    try:
        result = validate()
        if args.json:
            print(json.dumps(result, ensure_ascii=True))
        else:
            for item in result['comparisons']:
                print(item['key'] + ': ' + item['state'].upper())
            for limitation in result['limitations']:
                print('Limitation: ' + limitation)
        return exit_code(result)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError):
        print('Validation could not complete; no report saved.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
