#!/usr/bin/env python

import scrypt
import sys
import array

def int_parse(str):
	return int(str, 0)

def get_args():
	import argparse

	parser = argparse.ArgumentParser()
	parser.add_argument('--passwd', required=True, help='Password')
	parser.add_argument('--salt', required=True, help='Salt')
	parser.add_argument('--N', required=True, type=int_parse, help='N')
	parser.add_argument('--r', required=True, type=int_parse, help='r')
	parser.add_argument('--p', required=True, type=int_parse, help='p')
	parser.add_argument('--dklen', required=True, type=int_parse, \
			help='dklen')

	return parser.parse_args();

def main():
	args = get_args()
	dk = scrypt.hash(args.passwd, args.salt, args.N, args.r, args.p, \
			 args.dklen)
	f = sys.stdout
	i = 0;
	for x in array.array("B", dk):
		f.write("0x" + '{0:02x}'.format(x) + ",")
		i = i + 1
		if i % 8 == 0:
			f.write("\n");
		else:
			f.write(" ");

if __name__ == "__main__":
	main()
