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
import sys, os
import argparse
import requests
import csv

def whiteList(whitefile):
    white_list = []
    for wl_hashes in whitefile:
        white_list.append(wl_hashes.strip())
    return white_list;

def inputList(infile):
    infile_list = []
    for hashes in infile:
        infile_list.append(hashes.strip())
    return infile_list;

def compareLists(wl, infl):
    remaining_hashes = {}
    for files in infl:
        file_hashes = files.split("  ")[0].strip()
        files_path = files.split("  ")[1].strip()
        if file_hashes.lower() in wl:
            pass
        else:
            remaining_hashes[file_hashes] = files_path
    return remaining_hashes;

def vtResults(hash_remain, api_key):
    '''
    Key is the MD5 hash. 
    Value is the file path.
    '''
    vt_hits = {}
    for key, value in hash_remain.iteritems():
        params = {'apikey': api_key, 'resource': key}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = response.json()
        if json_response['response_code'] == 0:
            vt_hits[key] = value, "None", "Has not been scanned before"
        elif json_response['positives'] >= 1:
            ratio = str(json_response['positives']) + "/" + str(json_response['total'])
            url = json_response['permalink']
            vt_hits[key] = value, ratio, url
        else:
            pass
    return vt_hits

def outputResults(vthits):
    vtwriter = csv.writer(sys.stdout)
    vtwriter.writerow(['Hash', 'Filename', 'Ratio', 'URL'])
    for key, value in vthits.iteritems():
        vtwriter.writerow([key, value[0], value[1], value[2]])

def main():
    parser = argparse.ArgumentParser(description='Look up hashes against a white list then look at VT.')
    parser.add_argument('-wl', '--whitelist', help='Path to your whitelist.')
    parser.add_argument('-f', '--infile', help='Path to the input hashes.')
    parser.add_argument('-a', '--api', help='Virus Total API Key. If none submitted it will default to static.')
    args = parser.parse_args()
    if args.whitelist:
        whitefile = open(args.whitelist, 'r').readlines()
    else:
        print "You need to specify the whitelist."
    if args.infile:
        infile = open(args.infile, 'r').readlines()
    else:
        print "You need to specify the hashes from your dump."
    if args.api:
        api_key = args.api
    else:
        api_key = 'YOUR_PRIVATE_API_KEY'

    wl = whiteList(whitefile)
    infl = inputList(infile)
    hash_remain = compareLists(wl, infl)
    vthits = vtResults(hash_remain, api_key)
    outputResults(vthits)
if __name__ == "__main__":
    main()
