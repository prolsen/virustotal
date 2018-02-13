Virus Total Lookup Scripts
===========================

This is just a small collection of VirusTotal lookup scripts i've written to help automate a couple tasks. My IR collection script collects autoruns output and I also run md5deep against a few areas often visited by malware (%appdata%, %temp%, system32, etc.) I always found myself right clicking on hashes in autoruns and looking them up on the internet. That's too time consuming so I wanted some form of automation. Likewise with the md5deep output. It takes too long to review without some form of automation.

The code it pretty bad, but it seems to work on the output I have tested. Hit me up if you get any errors or if you have suggestions for making them better/more effecient.


Autoruns Virus Total Lookup
============================
This will take text output from Microsoft's Autoruns tool, "parse it" and then look up the hashes via virus total.

		autohash.py -h
		usage: autohash.py [-h] [-f INFILE]

		Take autoruns txt output and look the hashes up on VirusTotal.
		
		optional arguments:
		  -h, --help            show this help message and exit
		  -f INFILE, --infile INFILE
		                        Path to autoruns text file.

You will need to run autorunsc.exe first and get some output.

autorunsc.exe -f /accepteula * >> Autostart_All.txt

python vt_public_autorun.py -f /Users/patrick.olsen/Desktop/Autostart_All.txt

		file,hash,malname,count
		c:\windows\system32\userinit.exe,61ac3efdfacfdd3f0f11dd4fd4044223,None,0
		c:\program files\hp hd webcam [fixed]\monitor.exe,54304fba24eb4d7ad85df29485aaac96,None,0
		c:\program files\hewlett-packard\hp hotkey support\qlbcontroller.exe,cac998c8d3e0d56d2f245e42c2f70809,None,0

MD5deep Virus Total Lookup
=============================
This "parses" the output from md5deep, bounces up the hashes against a whitelist, then the remaining files that are not in the whitelist it will query virus total.

python vt_public.py -h

		usage: vt_public.py [-h] [-wl WHITELIST] [-f INFILE] [-a API]

		Look up hashes against a white list then look at VT.

		optional arguments:
		  -h, --help            show this help message and exit
		  -wl WHITELIST, --whitelist WHITELIST
		                        Path to your whitelist.
		  -f INFILE, --infile INFILE
		                        Path to the input hashes.
		  -a API, --api API     Virus Total API Key. If none submitted it will default
		                        to static.

First run md5deep and output it to a file.

md5deep.exe -r -l -s "<path>" >> Hashes.txt

		2e83ec18c281102c5dbb423f6df57cf3 C:\Windows\bootstat.dat has not been scanned before.
		b30afc59f449c93d7030cd85d28a8c45 C:\Windows\certenroll.log has not been scanned before.
		bd3d4eabd379a59f336b099a48d382f0 C:\Windows\CertReq.log has not been scanned before.
		1ccc16aa7c32c1395fa95311229fbd83 C:\Windows\certutil.log has not been scanned before.
		313a22f8f16b6bc1cfe857737dfc2935 C:\Windows\aksdrvsetup.log has not been scanned before.
		963f5385ff22824af6a9b1429555d4a2 C:\Windows\certocm.log has not been scanned before.
		fbcbc70c8f2d4ce235f32151860ee79d C:\Windows\dchcfg32.exe 0 / 47
		9966b5dfeb602224d1854da81e603cf7 C:\Windows\dcmdev64.exe 0 / 48
		16c4d2e3935f1a0934d115959426268c C:\Windows\DELL_VERSION has not been scanned before.
		682ae0ffa6a865a8d137c43139bb4bcd C:\Windows\diagerr.xml 0 / 47
		49d9fb48f4c2078fa8e663d7c5758259 C:\Windows\DirectX.log has not been scanned before.
		5bf963f4626737e5c342fb58827a6718 C:\Windows\DtcInstall.log has not been scanned before.
		c696428435782e9c7646f590a360b85d C:\Windows\fmprog.ini has not been scanned before.

vt_public.py -wl whitelist.txt -f Hashes.txt
		
		Hash,Filename,Ratio,URL
		0f50ed258404f304a9a9822e876f641d,C:\she.exe,25/55,https://www.virustotal.com/file/e00e7d8891771a68f937e756579662eec5ca88ffe51f4ac06409c4aaad3e3cc9/analysis/1409508592/
		035a5e4dc48e1acc8752c68fd6ae3860,C:\we.exe,7/55,https://www.virustotal.com/file/075a1015bca666baf6d5b1ba4297829b6e2b74559541a14349cf8e6d5799a9e5/analysis/1410204209/
		60242ad3e1b6c4d417d4dfeb8fb464a1,D:\i.exe,7/55,https://www.virustotal.com/file/1db30d5b2bb24bcc4b68d647c6a2e96d984a13a28cc5f17596b3bfe316cca342/analysis/1410204326/
		7b6216d0fefc26bffb6fc1db623fca57,C:\you.exe,6/55,https://www.virustotal.com/file/497f50095f71e6bf3fb56b547cf05e3c83d3ebcf60e9885ec51c11311109a0aa/analysis/1410204254/
		9a8bd751239695a4112321fe2ceb9151,C:\it.exe,7/55,https://www.virustotal.com/file/8937012dcdbddf9c960d920cc1724be5e78cef373b5ac460644b0f366105e63a/analysis/1410204263/
