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
import csv
import ipaddress

cc = {cc.upper() for cc in sys.argv[1:]}

version_fields = ('version', 'registry', 'serial', 'records', 'startdate', 'enddate', 'UTCoffset')
summary_fields = ('registry', '*', 'type', '*', 'count', 'summary')
stats_fields = ('registry', 'cc', 'type', 'start', 'value', 'date', 'status', 'extensions')

blacklist = []
version = []
summary = []
records = []

reader = csv.DictReader((line for line in sys.stdin if line and line[0] != '#'), fieldnames=version_fields, delimiter='|')
for version_line in reader:
    version.append(version_line)

    reader.fieldnames = summary_fields
    for _ in range(3):
        summary.append(next(reader))

    reader.fieldnames = stats_fields
    for _ in range(int(version[-1]['records'])):
        try:
            records.append(next(reader))
        except StopIteration:
            break

    reader.fieldnames = version_fields

for record in records:
    if record['cc'] in cc:
        if record['type'] == 'ipv4':
            startip = ipaddress.IPv4Address(record['start'])
            endip = ipaddress.IPv4Address(int(startip) + int(record['value']) - 1)
            blacklist.extend(ipaddress.summarize_address_range(startip, endip))
        elif record['type'] == 'ipv6':
            blacklist.append(ipaddress.IPv6Network((record['start'], record['value'])))

for net in blacklist:
    print(net if net.num_addresses > 1 else net.network_address)

