#!/bin/sh
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

CC="
	
"

set -- $(echo $CC $@ | tr "[:upper:][:space:]" "[:lower:]\n" | sort -u)

(
curl --retry 5 --fail-early --show-error --silent \
	https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest \
	https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest \
	https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest \
	https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest \
	https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest \
| ./nets_from_stats.py $@ &
curl --retry 5 --fail-early --show-error --silent \
	https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz \
	https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz \
	https://ftp.apnic.net/apnic/whois/apnic.db.organisation.gz \
	https://ftp.apnic.net/apnic/whois/apnic.db.role.gz \
	https://ftp.apnic.net/apnic/whois/apnic.db.mntner.gz \
	https://ftp.ripe.net/ripe/dbase/ripe.db.gz \
	https://ftp.afrinic.net/pub/dbase/afrinic.db.gz \
	https://ftp.lacnic.net/lacnic/dbase/lacnic.db.gz \
	https://ftp.arin.net/pub/rr/arin.db.gz \
| gzcat | ./nets_from_whois.py $@ &
cat malnets.txt
) | ./summarize.py > pf.blacklist

grep \\. pf.blacklist | (echo define blacklist_ipv4 = {; while read net; do printf "\t%s,\n" "$net"; done; echo "}") > nftables.blacklist_ipv4
grep : pf.blacklist | (echo define blacklist_ipv6 = {; while read net; do printf "\t%s,\n" "$net"; done; echo "}") > nftables.blacklist_ipv6

(printf "{\n    \"name\": \"Blacklist\",\n    \"description\": \"Country blocks for %s\",\n    \"denied-remote-domains\": [\"%s\"" "$(echo $@ | tr [:lower:] [:upper:])" "$1"; shift; for cc in $@; do printf ", \"%s\"" "$cc"; done; read net; printf "],\n    \"denied-remote-addresses\": [\"%s\"" "$net"; while read net; do printf ", \"%s\"" "$net"; done; printf "]\n}") < pf.blacklist > blacklist.lsrules
