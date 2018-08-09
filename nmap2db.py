#!/usr/bin/env python3

import os
import csv
import time
import pprint
import argparse
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
