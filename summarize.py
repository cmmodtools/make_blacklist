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
from ipaddress import *
from itertools import chain

networks4 = []
networks6 = []

for line in sys.stdin:
    try:
        net = ip_network(line.strip())
    except ValueError:
        continue

    if (net.version == 4):
        networks4.append(net)
    elif (net.version == 6):
        networks6.append(net)

for net in chain(collapse_addresses(networks4), collapse_addresses(networks6)):
    print(net if net.num_addresses > 1 else net.network_address)
