#!/usr/bin/env python3
#
#  Copyright (C) 2023-2024 Michal Roszkowski
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import sys
import ipaddress

sys.stdin.reconfigure(encoding='utf-8')
sys.stdin.reconfigure(errors="ignore")

cc = {cc.upper() for cc in sys.argv[1:]}

blacklist=[]
whois={}
obj, objname, key = {}, '', ''
for line in sys.stdin:
    try:
        if line[0] == '#':
            continue
        elif line.isspace():
            raise IndexError
        line = line.partition(':')

        if not line[1] or ' ' in line[0]:
            if not obj:
                continue
            line = ('', '', ''.join(line))
        else:
            key = line[0]
            if not obj:
                objname = key

        value = line[2].strip()
        obj[key] = obj[key] + '\n' + value if key in obj else value

    except IndexError:
        if obj:
            obj = {obj[objname]: obj} if objname != 'role' else {obj['nic-hdl']: obj}
            try:
                whois[objname].update(obj)
            except KeyError:
                whois[objname] = obj
            obj, objname, key = {}, '', ''

for objname in 'inetnum', 'inet6num':
    for key, obj in whois.get(objname, {}).items():
        objcc = {
                obj.get('country'),
                whois.get('role', {}).get(obj.get('admin-c'), {}).get('country'),
                whois.get('role', {}).get(obj.get('tech-c'), {}).get('country'),
                whois.get('mntner', {}).get(obj.get('mnt-by'), {}).get('country'),
                whois.get('organisation', {}).get(obj.get('org'), {}).get('country')
                } ^ { None }
        if not cc.isdisjoint(objcc):
            net = obj[objname].split()
            try:
                endip = ipaddress.IPv4Address(net[2])
                startip = ipaddress.IPv4Address(net[0])
                blacklist.extend(ipaddress.summarize_address_range(startip, endip))
            except IndexError:
                try:
                    blacklist.append(ipaddress.ip_network(obj[objname]))
                except ValueError:
                    net = obj['inetnum'].split('/')
                    net[0] = net[0].split('.')
                    for _ in range(4 - len(net[0])):
                        net[0].append('0')
                        
                    blacklist.append(ipaddress.IPv4Network(('.'.join(net[0]), net[1])))

for net in blacklist:
    print(net if net.num_addresses > 1 else net.network_address)

