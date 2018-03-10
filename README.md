## EFIgy

### What is EFIgy?

EFIgy is a RESTful API and client that helps Apple Mac users determine if they are running the expected EFI firmware version given their Mac hardware and OS build version. 

This small tool is part of the output from _'The Apple of your EFI'_ research by Pepijn Bruienne ([@bruienne](https://twitter.com/bruienne)) and Rich Smith ([@iodboi](https://twitter.com/iodboi)) 
released at [Ekoparty #13](https://ekoparty.org) on September 29th and discussed in this [blogpost](https://duo.com/blog/the-apple-of-your-efi-mac-firmware-security-research) and this [technical paper](https://t.co/GarDxCwQrw).

### \[NEW\] EFI check only

A new commandline option is now available to show the use of the new API endpoint that just checks whether your EFI version is up to date, older or newer than the expected version.
To use this new API simply use the `-o` (`--only-efi`) option`:

```
$ ./EFIgyLite_cli.py -o
...
<snipped for brevity>
...
Your firmware version MBP132.0233.B00 is the expected one for a MacBookPro13,2 running build 17D102. Smile, today is a good day :-)
```

The API endpoint being called is `/apple/up2date/{mac_model_code}/{build_number/{efi_version}` and it will return a json message in the standard format containing one of the following message bodies:

* `up2date` - Indicates that the supplied EFI version is the one that is expected for the supplied combination of Mac model and OS build number.
* `outofdate` - Indicates that the supplied EFI version is older than expected for the supplied combination of Mac model and OS build number.
* `newer` - Indicates that the supplied EFI version is the newer than expected for the supplied combination of Mac model and OS build number. This could be because the system previously had a beta or pre-release version of macOS installed and then downgraded to a stable OS version that shipped with older EFI firmware.
* `model_unknown` - Indicates the supplied Mac model was not one in the EFIgy Server dataset, or is in an incorrect format (use Mac model ID's in this format `MacBookPro13,2`).
* `build_unknown` - Indicates the supplied OS build was not one in the EFIgy Server dataset.

For example the json returned from this endpoint would look like:

```
{"msg": "up2date"}
```

### Support for 10.13.x

Finally there is the data for EFI versions in macOS 10.13.x in the API server so now you can check your versions for newer systems as well.
The client and server also more gracefully handle situations where the system is using a beta/dev build of the OS.

### Batch mode

EFIgy now supports a batch mode allowing you to split the collection of data from a fleet of Macs and the submission of that data to the API into two distinct steps. 
This means you can more easily make use of whatever your favorite config management solution is (osquery, chef, puppet etc) to gether the required data from endpoints, package that into a simple JSON format and then have the EFIgy client submit the data from each of the endpoints to the API and get the results.

To use batch mode do the following:

```
$ python ./EFIgyLite_cli.py -b path_to_json_input.json
```

Where `path_to_json_input.json` is the file containing the json representation of the endpoint systems information.

The format of the json input file is as follows:

```
{"1.2.3.4":
          {"board_id": "Mac-66E35819EE2D0D05",
            "smc_ver": "2.37f20",
            "build_num": "16G29",
            "rom_ver": "MBP132.0226.B25",
            "hw_ver": "MacBookPro13,2",
            "os_ver": "10.12.6",
            "sys_uuid": "12345678-1234-1234-1234-1234567890AB",
            "mac_addr": "b4:bf:b4:b1:b6:bc"},

  "a_mac_host.local":
          {"board_id": "Mac-66E35819EE2D0D05",
            "smc_ver": "2.37f21",
            "build_num": "16G07",
            "rom_ver": "MBP132.0226.B20",
            "hw_ver": "MacBookPro12,1",
            "os_ver": "10.12.4",
            "sys_uuid": "12345678-1234-1234-1234-1234567890CD",
            "mac_addr": "a4:af:a4:a1:a6:ac"}

}

```

With new key-value pairs for each endpoint that an API lookup is required for.

Each of the elements is explained below:

* `<ip_addr/hostname>` - The key to each dictionary is a unique identifier for an endpoint, most usually the IP address or hostname but you can use whatever you like. This value is for your own reference and is not sent to the API.
* `board_id` - This is the board ID of the endpoint and should start with the `Mac-` prefix
* `smc_ver` - This is the version of the SMC ROM on the endpoint
* `build_num` - This is the OS build number that is running on the endpoitn
* `rom_ver` - This is the EFI ROM version that is running on the endpoint
* `hw_ver` - This is the Mac model of the endpoint, in Apple longhand format e.g. `MacBookPro13,2`
* `os_ver` - This is friendly OS version running on the endpoint in Major/Minor/Micro format e.g. `10.12.6` (NOTE: will be deprecated in future)
* `sys_uuid` - This is the system UUID of the endpoint. *IMPORTANT:* This value is psuedononymised by the EFIgy client *before* being sent to the API. The psuedononymisation takes the form of a salted hash as described in the readme below. The real system UUID is *not* submitted to the API.
* `mac_addr` - This is the MAC address of the endpoint, this is purely used as a salt for the psuedononymisation of the system UUID. The MAC address is *not* submitted to the API.

There is an example batch jason file in the repo named `batch_input_example.json`


The use of batch mode means system administrators can more easily check large sets of endpoints against the endpoints and not have multiple systems making outbound requests to the API.

### Output and save results in JSON format

It is now possible to have the results from the EFIgy API represented in JSON format to more easily save and parse the results that come back from the API.

To have the results represented in JSON format use the `-j` switch as shown below:

```
$ python ./EFIgyLite_cli.py -j /tmp/my_results.json

```

Where `/tmp/my_results.json` is the file you want the results written to.

If you would like the JSON results written to stdout use `-` as the path:

```
$ python ./EFIgyLite_cli.py -j -

```

If you would like to supress all other output and just have the JSON formatted results out use `-j -` in combination with the `-q` (quiet) switch:

```
$ python ./EFIgyLite_cli.py -q -j -

```

How you choose to process the json formatted results from here is up to you, but you have the full response from the API for each endpoint that was queried.


### Specify path of cacert.pem file

Simple additon of the `-c` switch to allow the path of a cacert file to be specified directly. Under normal circumstances this shouldn't be needed as either the `certifi` will be used, or the `cacert.pem` file in this repo if the `certifi` module is not present.
 
To use a specific `cacert.pem` of your choosing simply do:

```
$ python ./EFIgyLite_cli.py -c /tmp/my_special_cacert.pem

```

Where `/tmp/my_special_cacert.pem` is the path to the `cacert.pem` file that you want to use.

If the `-c` switch is used then the supplied `cacert.pem` will override whatever file is returned by the `certifi` module.

### What's the quickest way for me to play with it?

If you just want to test one off systems then there is now a convenient little webapp to test systems with.

Go to [https://check.efigy.io](https://check.efigy.io) and see what it tells you.

If you ware wanting to check multiple systems or interface with efigy programatically you are much better to use the EFIgy client in this repo or call the RESTful API directly.


### EFIgy GUI

There is now a GUI client for the EFIgy API which can be found [here](https://github.com/duo-labs/EFIgy-GUI)


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

A current limitation is that this client is currenlty aimed at sysadmins / technical users rather than a more typical home user of a Mac. For home users to check their Mac's on a one off basis then either use the webapp [https://check.efigy.io]() or use the EFIgy-GUI app [https://github.com/duo-labs/EFIgy-GUI](). 

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

### Requirements

EFIgy requires [pyobjc](https://pythonhosted.org/pyobjc/) library to work. You can install this dependency via:

```
$ pip install -r requirements.txt
```

### I found a bug !

Please send it to us and we will try and fix it. If you could reproduce the issue using the `--debug` command line switch to get some extra info for you report that would be awesome and very much appreciated.

### Future?

This is only the start of what we are going to release and we hope to continue to build this dataset and API into one that is comprehensive and useful to a variety of people. Our research will continue and
we will share new findings as we have them.

Thanks for your interest in the project!
