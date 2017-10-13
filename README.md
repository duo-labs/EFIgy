## EFIgy

### What is EFIgy?

EFIgy is a RESTful API and client that helps Apple Mac users determine if they are running the expected EFI firmware version given their Mac hardware and OS build version. 

This small tool is part of the output from _'The Apple of your EFI'_ research by Pepijn Bruienne ([@bruienne](https://twitter.com/bruienne)) and Rich Smith ([@iodboi](https://twitter.com/iodboi)) 
released at [Ekoparty #13](https://ekoparty.org) on September 29th and discussed in this [blogpost](https://duo.com/blog/the-apple-of-your-efi-mac-firmware-security-research) and this [technical paper](https://t.co/GarDxCwQrw).


### [NEW] What's the quickest way for me to play with it?

If you just want to test one off systems then there is now a convenient little webapp to test systems with.

Go to [https://check.efigy.io]() and see what it tells you.

If you ware wanting to check multiple systems or interface with efigy programatically you are much better to use the EFIgy client in this repo or call the RESTful API directly.


### How come it says EFIgy Lite ?

This is the first release of a larger set of code, apps, and datasets coming from the research and is a subset of the final functionality. Rather than wait until everything has finalised and is ready for release
we wanted to release a core piece so that people could easily test their EFI versions against the expected EFI versions that were gathered during the research. Ekoparty took it's toll and once we have recovered and got some sleep
more will be coming so keep checking back. We will announce updates on Twitter when they happen.

The code works but will be cleaned up further in future, there may well be some bugs (it's a v0.2 'post-Ekoparty #13 very tired release' version for a reason!) so if you find any please let us know and we'll fix them as quickly as we can.
 
### How does it work?

It is a pretty straight forward Python 2.7 client, invoke it with either `python EFIgyLite_cli.py` or just `./EFIgyLite_cli.py`. If you do not have the `certifi` python module installed then make sure you also 
grab the `cacert.pem` file and have it in the same directory as the `EFIgyLite_cli.py` script otherwise requests to the API will likely fail with SSL errors. There are currently a small number of command line options
and you can see these along with descriptions via the `-h` switch e.g. `python EFIgyLite_cli.py -h`.

The datasets and work to collate the information all happens on the backend EFIgy API as this allows us to continually add to and improve the datasets that are being queried by the client. When you run the client 
you will be shown the information that is being sent to the API and prompted to allow or deny the request. There is no PII being sent to the API, a hashed and salted SysUUID is being sent along with the various version 
numbers so as to help us see number of distinct systems that have queried the API but there is nothing to stop you sending a different value for the SysUUID should you wish (it will just slow our continued research
into the space of getting the most comprehensive set of Apple EFI version information and making it available to people to use).

**IMPORTANT:**
 
**The client works entirely in userspace and does not touch the system's EFI firmware at all, it just grabs some version numbers and sends them to the API so as we can make the prediction of what version of
EFI you should probably be running, and if you find you are deviating from the expected version making you aware so as you can update.**

### Limitations

Currently the EFIgy API only supports OS X/macOS versions 10.10, 10.11 and 10.12 as they were the versions researched and are what our datasets currently comprise. An update to support macOS 10.13 will be released shortly once we have the 
datasets collected and verified.

Another limitation is that this client is currenlty aimed at sysadmins / technical users rather than a more typical home user of a Mac. A simpler webapp version that uses the same backend EFIgy API will be released soon to allow home users
to more easily check their EFI versions on a one off basis.

## Example output

```
$ ./EFIgyLite_cli.py

EFIgyLite API Information:
	API Version: 0.2
	Updated On: Oct 3 2017, 16:44


Enumerated system informaton (This data will be sent to the API in order to determine your correct EFI version):
	Hashed SysUUID   : 44c3cfc635daa575636ebb88a78d7c88c54dabdb60ffaddcb8d7c02845955710
	Hardware Version : MacBookPro13,2
	Boot ROM Version : MBP132.0226.B25
	SMC Version      : 2.37f20
	Board-ID         : Mac-66E35819EE2D0D05
	OS Version       : 10.12.6
	Build Number     : 16G29

[?] Do you want to continue and submit this request? [Y/N]  y

EFI firmware version check:
	[+] SUCCESS - The EFI Firmware you are running (MBP132.0226.B25) is the expected version for the OS build you have installed (16G29) on your MacBookPro13,2

Highest build number check:
	[+] SUCCESS - You are running the latest build number (16G29) of the OS version you have installed (10.12.6)

Up-to-date OS check:
	[+] SUCCESS - You are running the latest major/minor/micro version of the OS you have installed (10.12.6)

```

### I found a bug !

Please send it to us and we will try and fix it. If you could reproduce the issue using the `--debug` command line switch to get some extra info for you report that would be awesome and very much appreciated.

### Future?

This is only the start of what we are going to release and we hope to continue to build this dataset and API into one that is comprehensive and useful to a variety of people. Our research will continue and
we will share new findings as we have them.

Thanks for your interest in the project!
