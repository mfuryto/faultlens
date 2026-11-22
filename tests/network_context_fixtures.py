"""Invented numeric local context; never collected from a real server."""
import json
from faultlens.commands import Command,Result


def reply(command,maximum=False):
    if command==Command.NETWORK_ADDRESSES:
        rows=[{'ifindex':index+1,'ifname':'net'+str(index),'flags':['UP','LOWER_UP'],'operstate':'UP',
               'addr_info':[{'family':'inet','local':'192.0.2.1','prefixlen':24,'scope':'global'},
                            {'family':'inet6','local':'2001:db8::1','prefixlen':64,'scope':'global'}]} for index in range(128 if maximum else 1)]
    elif command in {Command.NETWORK_ROUTES4,Command.NETWORK_ROUTES6}:
        v4=command==Command.NETWORK_ROUTES4
        rows=[{'dst':'default','gateway':'192.0.2.254' if v4 else '2001:db8::ff','dev':'net0','table':254,'protocol':'static','metric':index} for index in range(256 if maximum else 1)]
    elif command==Command.SOCKET_OWNERS:
        return Result('completed',''.join(f'tcp ESTAB 0 0 192.0.2.1:{10000+i} 198.51.100.1:443 users:(("synthetic-worker",pid=42,fd={i+3}))\n' for i in range(512 if maximum else 1)),0)
    else:return Result('missing')
    return Result('completed',json.dumps(rows),0)
