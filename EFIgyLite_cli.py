#!/usr/bin/env python
#-----------------------------------------------------------
# Filename      : EFIgyLite_cli.py
#
# Description   : Initial EFIgy client that uses the EFIgy
#                 API to check the EFI firmware version
#                 your Mac is running is the expected one.
#                 OS X/macOS 10.10,10.11,10.12 only for now.
#
# Created By    : Rich Smith (@iodboi)
# Date Created  : 3-Oct-2017 18:03
#
# Version       : 0.2 (post-Ekoparty #13 very tired release)
#
# License       : BSD 3-Clause
#-----------------------------------------------------------


NAME     = "EFIgyLite_cli"
VERSION  = "0.2"
CODE_URL = "https://efigy.io"

import os
import sys
import json
import time
import types
import hashlib
import logging
import urllib2
import argparse
import commands
import platform
from uuid import getnode
from plistlib import readPlistFromString
from subprocess import Popen, PIPE

##For obvious reasons this only works on Macs
if platform.system() != "Darwin":
    print "[!] This application only supports Apple Macs at this time. Sorry :'("
    sys.exit(1)

##No support for 10.13 at this time
if int(platform.mac_ver()[0][3:5]) >= 13:
    print "[!] Unsupported version of macOS detected '%s'. %s currently only supports 10.10.x-10.12.x"%(platform.mac_ver()[0], NAME)
    print "Exiting ....."
    sys.exit(1)

##Get absolute path of where this module is executing from
MODULE_LOCATION = os.path.abspath(os.path.dirname(__file__))

##Set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EFIgyCliError(Exception):

    def __init__(self, message, last_response):
        print "\n\nError: %s"%(message)
        print "\nMost recent response received from the API endpoint:"
        try:
            response_err_data = json.loads(last_response.read())
            print "\n\tURL: %s\n\tCode: %s\n\tMessage: %s\n"%(last_response.url, response_err_data["Code"], response_err_data["Message"])

        except:
            response_err_data = last_response.read()
            print "\n\tURL: %s\n\tResponse: %s"%(last_response.url, response_err_data)


class EFIgyCli(object):


    def __init__(self, api_server_url, quiet=False, debug=False, log_path=""):

        ##Display options
        self.quiet = quiet
        self.debug = debug

        ##set up logging
        self.log_fo = None
        self.log_path = ""
        if log_path:
            try:
                self.log_path = os.path.join(log_path, "%s_%s.log"%(NAME,str(time.time()).replace(".","_")))
                self.log_fo = open(self.log_path, "wb")
                self.message("Writing output log to %s" % (self.log_path))
            except Exception, err:
                sys.stderr.write("[!] Error opening specified log file at '%s' - %s"%(self.log_path, err))

        ##Set initial variables
        self.api_server    = api_server_url
        self.results       = {}
        self.last_response = None

        ##Set the salt to be the MAC address of the system, using the MAC as a salt in this manner
        ## helps ensure that the hashed sysuuid is psuedononymous. We don't want to know the sysuuid's
        ## value, but we do want it to be unique however. The Salt value is never submitted to the API
        self.salt = hex(getnode())

        ##See if we can get the latest cacerts from the certifi module, if it's not available pull in a bundled one (may not be as up to date)
        ## This needs to be set explicitly in GET/POSTS to the AWS API otherwise you get SSL warnings and calls fail
        try:
            import certifi
            self.cacert_path = certifi.where()
            logger.debug("[+] Certifi module found")
        except ImportError:
            logger.debug("[-] Certifi module not found, falling back to bundled cecert.pem file")
            self.cacert_path = os.path.join(MODULE_LOCATION, "cacert.pem")
            ##Check existence of the cacert.pem file
            try:
                os.stat(self.cacert_path)
                logger.debug("[+] cacert file location: '%s'" % (self.cacert_path))
            except OSError:
                logger.debug("[-] Local cacert.pem file not found at location '%s'. Please check this location or pip install certifi."%(self.cacert_path))
                raise


    def message(self, data, newline="\n"):
        """
        Show info to the user depending on verbosity level
        :param data: - String of message to show
        :return:
        """
        #Are we logging to screen, file or both?
        if not self.quiet:
            print data

        if self.log_fo:
            self.log_fo.write(data+newline)
            self.log_fo.flush()


    def __make_api_get(self, api_path):
        """
        Wrapper to make an API GET request, return the response and handle errors
        :return: 
        """
        try:
            self.last_response = urllib2.urlopen(self.api_server+api_path, cafile=self.cacert_path)
            json_data = self.last_response.read()

        ##Check for errors
        except urllib2.HTTPError, err:
            error =  "API HTTP error [%s] - '%s'" % (err.code, err.read())
            raise EFIgyCliError(error, self.last_response)

        except urllib2.URLError, err:
            error = 'Problem calling API at location %s - %s'%(self.api_server+api_path, err)
            raise EFIgyCliError(error, self.last_response)

        ##Decode json response into an object
        try:
            ret = json.loads(json_data)
        except ValueError, err:
            error = "Problem deserialising data, expecting JSON.\nError: %s\nData: %s"%(err, json_data)
            raise EFIgyCliError(error, self.last_response)

        ##Return JSON deserialised object
        return ret


    def __make_api_post(self, api_path, data=None):
        """
        Wrapper to make an API POST request, return the response and handle errors
        :return:
        """
        headers = {"Content-type": "application/json", "Accept": "application/json"}
        x = json.dumps(data)

        try:
            req = urllib2.Request(self.api_server+api_path, x, headers)
            self.last_response = urllib2.urlopen(req, cafile=self.cacert_path)
            json_data = self.last_response.read()

        ##Check for errors
        except urllib2.HTTPError, err:
            error =  "API HTTP error [%s] - '%s'" % (err.code, err)
            raise EFIgyCliError(error, err)

        except urllib2.URLError, err:
            error = 'Problem calling API at location %s - %s'%(self.api_server+api_path, err)
            raise EFIgyCliError(error, self.last_response)

        ##Decode json response into an object
        try:
            ret = json.loads(json_data)
        except ValueError, err:
            error = "Problem deserialising data, expecting JSON.\nError: %s\nData: %s"%(err, json_data)
            raise EFIgyCliError(error, self.last_response)

        ##Return JSON deserialised object
        #print "DEBUG  - %s"%(ret), type(ret)
        return ret


    def _validate_response(self, response):
        """
        Validate the response that came back from the API, return True if it's good, False if bad

        :param response: API response, Dictionary expected
        :return: True if response if valid, False if not
        """
        ##Check for unexpected response - all should be JSON dicts that have already been deserialised
        if type(response) != types.DictionaryType:
            self.message("\t[!] ERROR - Unexpected value returned from the API: '%s'"%(response))
            return False

        ##Check for valid errors
        if response.has_key("error") and response.has_key("msg"):
            self.message("\t[!] ERROR - %s (%s)" % (response["msg"], response["timestamp"]))
            return False

        ##Is this a valid response message
        if response.has_key("msg"):
            return True

        ##Catch all...dictionary returned but does not contain expected keys? Who know's what's going on here?!
        else:
            self.message("\t[!] ERROR - Unexpected dictionary response returned from the API: '%s'"%(response))
            return False


    def __call__(self):

        try:
            self.message("\nEFIgyLite API Information:")
            api_version = self.__make_api_get("/version")
            if api_version["version"]!= VERSION:
                self.message("\n\t[!][!] EFIgyLite client version '%s' does not EFIgyLite API version '%s', bad things may happen please grab the latest version of the client from %s. [!][!]\n"%(VERSION,api_version,CODE_URL))
            self.message("\tAPI Version: %s\n\tUpdated On: %s\n\n" % (api_version["version"], api_version["updated"]))

            ##Get the local system data to send to API to find out relevant EFI firmware info
            submit_data = self.gather_system_versions()
            if not submit_data:
                self.cleanup()
                return

            ##Send the datas to the API
            self.results = self.submit_system_data()

            ##Is this a model of mac that is getting EFI updates?
            if self.check_fw_being_updated():
                ##If yes Are you running a Mac model that hasn't seen any FW update?
                ##Is your firmware patched to the expected level given your OS
                self.check_fw_versions()

            ##Are running the latest build number?
            self.check_highest_build()

            ##Are you running an out of date OS minor version?
            self.check_os_up_to_date()

            ##Clean up
            self.cleanup()

        except EFIgyCliError, err:
             sys.stderr.write("%s"%(err))


    def gather_system_versions(self):
        """
        Get versions of EFI, Boot ROM, OS & Mac Device as well as the SysUUID
        :return:
        """
        self.message("Enumerated system informaton (This data will be sent to the API in order to determine your correct EFI version): ")

        ##Get  Mac model ID, EFI & SMC ROM versions
        devnull = open(os.devnull, 'wb')
        sp_xml = Popen(["system_profiler", "-xml", "SPHardwareDataType"], stdout=PIPE, stderr=devnull).communicate()[0]
        self.hw_version  = readPlistFromString(sp_xml)[0]["_items"][0]["machine_model"]
        self.rom_version = readPlistFromString(sp_xml)[0]["_items"][0]["boot_rom_version"]
        self.smc_version = readPlistFromString(sp_xml)[0]["_items"][0]['SMC_version_system']

        ##We like the uniqueness of the platforms UUID but we want to preserve privacy - hash it with salt to psuedononymise
        self.h_sys_uuid  = hashlib.sha256(self.salt + readPlistFromString(sp_xml)[0]["_items"][0]["platform_UUID"]).hexdigest()

        ##Get the Board-ID, this is how EFI files are matched to running hardware - Nastee
        io_reg = [a.strip() for a in commands.getoutput('ioreg -p "IODeviceTree" -r -n / -d 1').split("\n") if "board-id" in a][0]
        self.board_id = io_reg[io_reg.find("<") + 2:io_reg.find(">") - 1]

        ## Get OS version
        self.os_version = commands.getoutput("sw_vers -productVersion")

        ## Get build number
        self.build_num  = commands.getoutput("sw_vers -buildVersion")

        ## Carve out the major version as we use this a bunch
        self.os_maj_ver = ".".join(self.os_version.split(".")[:2])

        self.message("\tHashed SysUUID   : %s" % (self.h_sys_uuid))
        self.message("\tHardware Version : %s" % (self.hw_version))
        self.message("\tBoot ROM Version : %s" % (self.rom_version))
        self.message("\tSMC Version      : %s" % (self.smc_version))
        self.message("\tBoard-ID         : %s" % (self.board_id))
        self.message("\tOS Version       : %s" % (self.os_version))
        self.message("\tBuild Number     : %s" % (self.build_num))

        if not self.quiet:
            agree = raw_input("\n[?] Do you want to continue and submit this request? [Y/N]  ").upper()
            if agree not in ["Y", "YES"]:
                self.message("[-] OK! Not sending request to the API. Exiting.....")
                return False

        return True


    def submit_system_data(self):
        """
        Send the System info to the API so as the expected EFI version and other data can be
        returned relevant to this system

        :return:
        """
        endpoint = "/apple/oneshot"
        data_to_submit = {"hashed_uuid":self.h_sys_uuid, "hw_ver":self.hw_version, "rom_ver":self.rom_version,
                          "smc_ver":self.smc_version, "board_id":self.board_id, "os_ver":self.os_version, "build_num":self.build_num}

        ##POST this data to the API to get relevant info back
        result_dict = self.__make_api_post(endpoint, data=data_to_submit)

        return result_dict


    def check_highest_build(self):
        """
        Given the OS version are you running, what is the highest available build number? Are you running it?
        :return:
        """
        if not self.results.get("latest_build_number"):
            self.results["latest_build_number"] = self.__make_api_get('/apple/"latest_build_number"/%s' % (self.os_maj_ver))

        self.message("\nHighest build number check:")

        ##Validate response from API
        if self._validate_response(self.results["latest_build_number"]):

            ##Valid response from API - now interpret it
            if self.results["latest_build_number"]["msg"] == self.build_num:
                self.message("\t[+] SUCCESS - You are running the latest build number (%s) of the OS version you have installed (%s)" % (self.build_num, self.os_version))
            else:
                self.message("\t[-] ATTENTION - You are NOT running the latest build number of your OS version (%s). Your build number is %s, the latest build number is %s" % (self.os_version, self.build_num, self.results["latest_build_number"]["msg"]))


    def check_os_up_to_date(self):
        """
        Given your major OS version are you running the latest minor patch?
        """
        if not self.results.get("latest_os_version"):
            self.results["latest_os_version"] = self.__make_api_get('/apple/latest_os_version/%s' % (self.os_maj_ver))

        self.message("\nUp-to-date OS check:")

        ##Validate response from API
        if self._validate_response(self.results["latest_os_version"]):

            ##Valid response from API - now interpret it
            if self.os_version != self.results["latest_os_version"]["msg"]:
                self.message("\t[-] ATTENTION - You are NOT running the most up to date version of the OS. Your OS version is %s, the latest versions is %s" % (self.os_version, self.results["latest_os_version"]["msg"]))
            else:
                self.message("\t[+] SUCCESS - You are running the latest major/minor/micro version of the OS you have installed (%s)" % (self.os_version))


    def check_fw_being_updated(self):
        """
        Does it look like this mac model is still receiving EFI firmware updates?
        :return:
        """
        if not self.results.get("efi_updates_released"):
            ##Call the API to see what the latest version of EFI you are expected to be runnign given OS ver and mac model
            self.results["efi_updates_released"] = self.__make_api_get('/apple/no_firmware_updates_released/%s' % (self.hw_version))

        ##Validate response from API
        if self._validate_response(self.results["efi_updates_released"]):

            #Check to see if this is a model that has seen any EFI firmware updates
            if self.results["efi_updates_released"]["msg"] == False:
                self.message("\nEFI firmware version check:")
                self.message("\t[-] ATTENTION - Your Mac model (%s) does not seem to have had any EFI updates released for it :'("%(self.hw_version))
                return False
            else:
                return True


    def check_fw_versions(self):
        """
        Compare this systems versions to the firmware table to see if FW is at latest versions
        :return:
        """
        if not self.results.get("latest_efi_version"):
            ##Call the API to see what the latest version of EFI you are expected to be runnign given OS ver and mac model
            self.results["latest_efi_version"] = self.__make_api_get('/apple/latest_efi_firmware/%s/%s' % (self.hw_version, self.build_num))

        self.message("\nEFI firmware version check:")

        ##Validate response from API
        if self._validate_response(self.results["latest_efi_version"]):

            ##Valid response from API - now interpret it
            if self.results["latest_efi_version"]["msg"] == self.rom_version:
                self.message("\t[+] SUCCESS - The EFI Firmware you are running (%s) is the expected version for the OS build you have installed (%s) on your %s" % (self.rom_version, self.build_num, self.hw_version))
            else:
                self.message("\t[-] ATTENTION - You are running an unexpected firmware version given the model of your system (%s) and OS build you have installed (%s). Your firmware %s, expected firmware %s.\nUpdate your firmware!!" % (self.hw_version, self.build_num, self.rom_version, self.results["latest_efi_version"]["msg"]))

    def cleanup(self):
        """
        Cleanup up so nothing dangles
        :return:
        """
        if self.log_fo:
            self.log_fo.close()


if __name__ == "__main__":


    ##Process command line args
    parser = argparse.ArgumentParser(description="%s v%s. App to assess Apple EFI firmware versions."%(NAME, VERSION), epilog="Visit %s for more information."%(CODE_URL))
    parser.add_argument("-l","--log", help="File to log output to")
    parser.add_argument("--debug",  action="store_true", default=False, help="Show verbose debugging output to stdout")
    parser.add_argument("-q", "--quiet",  action="store_true", default=False, help="Silence stdout output and don't ask to submit data to API. Use with the --log option")
    parser.add_argument("-v", "--version", action="store_true", default=False, help="Show client version")

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.version:
        print "%s %s"%(NAME, VERSION)
        sys.exit(0)

    if args.quiet:
        logger.setLevel(logging.WARNING)

    try:
        ##Prod Lite API server
        efigy_cli = EFIgyCli("https://w2fknz32ig.execute-api.us-west-2.amazonaws.com/api/", quiet=args.quiet, debug=args.debug, log_path=args.log)
        efigy_cli()
        print "\n"

    except Exception, err:
        print "[-] Fatal error in %s. Exiting....."%(NAME)
        if args.debug:
            import traceback
            print "\nError:\n\t%s"%(err)
            print "\n%s"%(traceback.format_exc())