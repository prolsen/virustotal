'''
The MIT License (MIT)

Copyright (c) 2014 Patrick Olsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Author: Patrick Olsen
'''

import argparse
import codecs
import re
import requests

def vtAutoScan(input_file):
	global hash_list
	hash_list = []
	file_line = []
	data = open(input_file, 'rb').readlines()
	print '%s,%s,%s,%s' % ("file","hash","malname","count")
	for i in range(len(data)):
		if data[i].replace('\x00', '').strip().startswith("MD5"):
			filename = data[i-2].replace('\x00', '').strip()
			hashes = data[i].replace('\x00', '').strip()[10:]
			params = {'apikey': '<INSERT_API_KEY_HERE>', 'resource': hashes}
			response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
			json_response = response.json()
			if json_response['response_code'] == 0:
				print '%s,%s,%s,%s' % (filename, hashes, "Not scanned before.",'None')
			else:
				if json_response['positives'] >= 2:
					print '%s,%s,%s,%s' % (filename, hashes, json_response['scans']['McAfee']['result'], str(json_response['positives']))
				else:
					pass
		else:
			pass

def main():
	parser = argparse.ArgumentParser(description='Take autoruns txt output and look the hashes up on VirusTotal.')
	parser.add_argument('-f', '--infile', help='Path to autoruns text file.')
	args = parser.parse_args()
	if args.infile:
	    input_file = args.infile
	else:
	    print "You need to specify your autoruns file."

	vtAutoScan(input_file)
if __name__ == "__main__":
    main()
