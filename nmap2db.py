#!/usr/bin/env python3

import os
import csv
import time
import pprint
import sqlite3
import argparse
from pathlib import Path
from libnmap.parser import NmapParser

def check_input(input):
	if os.path.isdir(input):
		print("Input appears to be a directory.  I don't know how to handle those (yet).")
		exit(1)
	elif os.stat(input).st_size == 0:
		print("Input is zero (0) bytes.  Nothing to do.")
		exit(1)
	elif not os.path.isfile(input):
		print("Input does not exist or wasn't specified.  Nothing to do.")
		exit(1)
	else:
		return True

def handle_args():
	parser = argparse.ArgumentParser(description="Convert nmap XML output to multiple database and office formats.")
	parser.add_argument('-v', '--verbose', dest='verbose', \
		help='Increased output.', default=False, \
		action='store_true')
	parser.add_argument('-i', '--input', dest='input', \
		help='Specify the path to the input file.', required=True)
	parser.add_argument('-o', '--output', dest='output', \
		help='Specify the path to the output file.  Only used \
			with Excel and CSV formats.')
	parser.add_argument('-d', '--database', dest='dbfile', \
		help='Specify the database name.  In case of SQLite, \
			this will be the filename.')
	parser.add_argument('format', metavar='FORMAT', \
		help='Specify the desired output format.')
	args = parser.parse_args()
	return args

def uniqify(ulist):
	# not order preserving
	set = {}
	map(set.__setitem__, ulist, [])
	return set.keys()

def uniq(ulist, idfun=None):
	# order preserving
	if idfun is None:
		def idfun(x): return x
	seen = {}
	result = []
	for item in ulist:
		marker = idfun(item)
		if marker in seen: continue
		seen[marker] = 1
		result.append(item)
	return result

def sort_ports(lot):
	# expects a list of tuples from nmapHost.get_open_ports() \
	# (or nmapHost.get_ports())
	portprot = dict()
	for tup in lot:
		if not tup[1] in portprot.keys():
			portprot[tup[1]] = list()
		portprot[tup[1]].append(tup[0])

	return portprot

def prep_csv_row(nmapHost):
	row = list()
	row.append(nmapHost.ipv4)
	names = ''
	if 'list' in str(type(nmapHost.hostnames)):
		if len(nmapHost.hostnames) > 1:
			names = ";".join(uniq(nmapHost.hostnames))
		elif len(nmapHost.hostnames) == 1:
			names = nmapHost.hostnames[0]
		else:
			names = 'UNRESOLVED'
			#print("{0} items in list object.".format(len(nmapHost.hostnames)))
			#exit(1)
	else:
		print("Got {0} object type, expected str() or list().".format(type(nmapHost.hostnames)))
		exit(1)

	row.append(names)
	os = ''
	if len(nmapHost.os_match_probabilities()) == 0:
		os = 'No Matches'
	else:
		if "list" in str(type(nmapHost.os_match_probabilities())):
			os = nmapHost.os_match_probabilities()[0]
		else:
			os = nmapHost.os_match_probabilities()
	#print("OS Obj Type: {0}".format(os))
	if 'NmapOSMatch' in str(type(os)):
		row.append(os.name)
		row.append(os.accuracy)
	else:
		row.append(os)
		row.append(0)
	row.append(nmapHost.status)
	row.append(sort_ports(nmapHost.get_open_ports()))
	if nmapHost.starttime is not None:
		row.append(nmapHost.starttime)
		row.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(nmapHost.starttime))))
	else:
		row.append(0)
		row.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(0)))
	if nmapHost.endtime is not None:
		row.append(nmapHost.endtime)
		row.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(nmapHost.endtime))))
	else:
		row.append(0)
		row.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(0)))
	dur = int(nmapHost.endtime) - int(nmapHost.starttime)
	row.append(dur)
	row.append(nmapHost.mac)
	row.append(nmapHost.vendor)
	row.append(nmapHost.scripts_results)
	
	return row

def create_table(table, dbfile):
	tsql = dict()
	tsql['nmap'] = 'CREATE TABLE nmap (sid INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, xmlversion TEXT, args TEXT, types TEXT, starttime INTEGER, startstr TEXT, endtime INTEGER, endstr TEXT, numservices INTEGER)'
	tsql['hosts'] = 'CREATE TABLE hosts (sid INTEGER, hid INTEGER PRIMARY KEY AUTOINCREMENT, ip4 TEXT, ip4num TEXT, hostname TEXT, status TEXT, tcpcount INTEGER, udpcount INTEGER, mac TEXT, vendor TEXT, ip6 TEXT, distance INTEGER, uptime TEXT, upstr TEXT)'
	tsql['sequencing'] = 'CREATE TABLE sequencing (hid INTEGER, tcpclass TEXT, tcpindex TEXT, tcpvalues TEXT, ipclass TEXT, ipvalues TEXT, tcptclass TEXT, tcptvalues TEXT)'
	tsql['ports'] = 'CREATE TABLE ports (hid INTEGER, port INTEGER, type TEXT, state TEXT, name TEXT, tunnel TEXT, product TEXT, version TEXT, extra TEXT, confidence INTEGER, method TEXT, proto TEXT, owner TEXT, rpcnum TEXT, fingerprint TEXT)'
	tsql['os'] = 'CREATE TABLE os(hid INTEGER, name TEXT, family TEXT, generation TEXT, type TEXT, vendor TEXT, accuracy INTEGER)'

	# set up the sqlite connection and create the table
	conn = sqlite3.connect(dbfile)
	c = conn.cursor()
	c.execute(tsql[table])
	conn.commit()
	conn.close()

def create_database(_dbfile):
	dbfile = Path(_dbfile)
	if dbfile.exists():
		if dbfile.is_dir():
			raise("{0} is a directory.  I don't know how to handle those (yet).")
		elif dbfile.is_file()():
			raise("File already exists.  Sheepishly refusing to overwrite.")
	else:
		for t in [ 'nmap', 'hosts', 'sequencing', 'ports', 'os' ]:
			create_table(t, _dbfile)

def main():
	args = handle_args()
	pp = pprint.PrettyPrinter(indent=4)
	
	if not args.output and not args.dbfile:
		print("You must specify an output appropriate for your selected \
			format (file or database).")
		exit(1)

	print("FORMAT: {0}".format(args.format))

	if check_input(args.input):
		nmap = NmapParser.parse_fromfile(args.input)
		print("Host status from scan: Up: {0} Down: {1} Total: {2}".format( \
			nmap.hosts_up, nmap.hosts_down, nmap.hosts_total))
		if args.format=='csv':
			print("Outputting to CSV format.")
			with open(args.output, 'w') as csvout:
				writer = csv.writer(csvout)
				writer.writerow(["IP","Hostname(s)","OS Guess","Accuracy",\
					"Host Status","Open Ports","Start Time - Epoch", \
					"Start Date", "End Time - Epoch", "End Date", "Duration", \
					"MAC Address","MAC Vendor","Scripts"])
				for h in nmap.hosts:
					#pp.pprint(h)
					row = prep_csv_row(h)
					# if verbose:
					#print(row)
					writer.writerow(row)
		else:
			raise Exception("Unknown format: {0}".format(args.format))
		
if __name__=='__main__':
	main()
