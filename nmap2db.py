#!/usr/bin/env python3

import csv
import pprint
import argparse
from libnmap.parser import NmapParser

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

def main():
	args = handle_args()
	pp = pprint.PrettyPrinter(indent=4)
	
	if not args.output and not args.dbfile:
		print("You must specify an output appropriate for your selected format.")
		exit(1)

	print("FORMAT: {0}".format(args.format))

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
				pp.pprint(h)
				names = ''
				if len(h.hostnames) > 1:
					names = ','.join(h.hostnames)
				else:
					names = h.hostnames[0]
				row = [h.address, names]
				print(row)
	else:
		raise Exception("Unknown format: {0}".format(args.format))
		
if __name__=='__main__':
	main()
