#!/usr/bin/python
#-----------------------------------------------------------
# Filename      : EFIgyLite_cli.py
#
# Description   : Initial EFIgy client that uses the EFIgy
#                 API to check the EFI firmware version
#                 your Mac is running is the expected one.
#                 OS X/macOS 10.10,10.11,10.12, 10.13 for now.
#
# Created By    : Rich Smith (@iodboi)
# Date Created  : 3-Oct-2017 18:03
#
# Version       : 0.4
#
# License       : BSD 3-Clause
#-----------------------------------------------------------

NAME = "EFIgyLite_cli"
VERSION = "0.2"
API_URL = "https://api.efigy.io"
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

# For obvious reasons this only works on Macs
if platform.system() != "Darwin":
    print "[!] This application only supports Apple Macs at this time. Sorry :'("
    sys.exit(1)

# If you're running older than OS X 10.10.x then EFI issues are the least
# of your security concerns
if int(platform.mac_ver()[0].split(".")[1]) < 10:
    print "[!] Unsupported version of macOS detected, %s currently only supports 10.10.x-10.13.x and you seem to be running %s. You're strongly encouraged to update to a more recent OS version as EFI versions are probably the least of your security concerns TBH." % (NAME, platform.mac_ver()[0])
    print "Exiting ....."
    sys.exit(1)

# Mac specific imports needed for direct Obj-C calls to get EFI & Board-ID's
# rather using iokit / system_profiler - Thanks to Piker-Alpha for the pointers on this. See their code here:
# https://github.com/Piker-Alpha/HandyScripts/blob/master/efiver.py &
# issue https://github.com/duo-labs/EFIgy/issues/8
import objc
from Foundation import NSBundle
IOKitBundle = NSBundle.bundleWithIdentifier_('com.apple.framework.IOKit')
functions = [
    ("IOServiceGetMatchingService", b"II@"),
    ("IOServiceMatching", b"@*"),
    ("IORegistryEntryFromPath", b"II*"),
    ("IORegistryEntryCreateCFProperty", b"@I@@I")
]
objc.loadBundleFunctions(IOKitBundle, globals(), functions)


# Get absolute path of where this module is executing from
MODULE_LOCATION = os.path.abspath(os.path.dirname(__file__))

# Set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EFIgyCliError(Exception):

    def __init__(self, message, last_response):
        print "\n\nError: %s" % (message)
        print "\nMost recent response received from the API endpoint:"
        try:
            response_err_data = json.loads(last_response.read())
            print "\n\tURL: %s\n\tCode: %s\n\tMessage: %s\n" % (last_response.url, response_err_data["Code"], response_err_data["Message"])

        except:
            response_err_data = last_response.read()
            print "\n\tURL: %s\n\tResponse: %s" % (last_response.url, response_err_data)


class EFIgyCli(object):

    def __init__(
            self,
            api_server_url,
            quiet=False,
            debug=False,
            log_path="",
            json_results="",
            batch_json_path="",
            cacert_path="",
            only_efi=False,
            yes=False):

        # Display options
        self.quiet = quiet
        self.debug = debug
        self.yes = yes

        # set up logging
        self.log_fo = None
        self.log_path = ""
        if log_path:
            try:
                self.log_path = os.path.join(
                    os.path.expanduser(
                        os.path.expandvars(log_path)), "%s_%s.log" %
                    (NAME, str(
                        time.time()).replace(
                        ".", "_")))
                self.log_fo = open(self.log_path, "wb")
                self.message("Writing output log to %s" % (self.log_path))
            except Exception as err:
                sys.stderr.write(
                    "[!] Error opening specified log file at '%s' - %s" %
                    (self.log_path, err))

        # Do we want results dumping as JSON?
        self.json_results = json_results

        # Are we using batch mode where we submit pre-collected values in an
        # json file to send to the API
        self.batch_json_path = batch_json_path
        self.json_batch_template = [
            "board_id",
            "smc_ver",
            "sys_uuid",
            "build_num",
            "rom_ver",
            "hw_ver",
            "os_ver",
            "mac_addr"]

        # Set initial variables
        self.api_server = api_server_url
        self.endpoints_to_check = {}
        self.results = {}
        self.last_response = None

        # Get terminal width for pretty printing
        try:
            self.term_width = int(
                commands.getoutput("stty size").split(" ")[1])
        except:
            self.term_width = 50

        # See if we can get the latest cacerts from the certifi module, if it's not available pull in a bundled one (may not be as up to date) unless user specified a path specifically
        # This needs to be set explicitly in GET/POSTS to the AWS API otherwise
        # you get SSL warnings and calls fail
        if cacert_path:
            self.cacert_path = os.path.expanduser(
                os.path.expandvars(cacert_path))

        else:
            # No cacert path specified so try certifi module, if that's not
            # there default to ./cacert.pem that is in the project repo
            try:
                import certifi
                self.cacert_path = certifi.where()
                logger.debug("[+] Certifi module found")
            except ImportError:
                logger.debug(
                    "[-] Certifi module not found, falling back to bundled cecert.pem file")
                self.cacert_path = os.path.join(MODULE_LOCATION, "cacert.pem")

        # Check existence of the cacert.pem file
        try:
            os.stat(self.cacert_path)
            logger.debug("[+] cacert file location: '%s'" %
                         (os.path.abspath(self.cacert_path)))
        except OSError:
            print "[-] Local cacert.pem file not found at location '%s'. Please check this location or pip install certifi." % (os.path.abspath(self.cacert_path))
            raise

        # Are we requesting server side compare of EFI only?
        self.only_efi = only_efi

    def message(self, data, newline="\n"):
        """
        Show info to the user depending on verbosity level
        :param data: - String of message to show
        :return:
        """
        # Are we logging to screen, file or both?
        if not self.quiet:
            print data

        if self.log_fo:
            self.log_fo.write(data + newline)
            self.log_fo.flush()

    def __make_api_get(self, api_path):
        """
        Wrapper to make an API GET request, return the response and handle errors
        :return:
        """
        try:
            self.last_response = urllib2.urlopen(
                self.api_server + api_path, cafile=self.cacert_path)
            json_data = self.last_response.read()

        # Check for errors
        except urllib2.HTTPError as err:
            error = "API HTTP error [%s] - '%s'" % (err.code, err.read())
            raise EFIgyCliError(error, self.last_response)

        except urllib2.URLError as err:
            error = 'Problem calling API at location %s - %s' % (
                self.api_server + api_path, err)
            raise EFIgyCliError(error, self.last_response)

        # Decode json response into an object
        try:
            ret = json.loads(json_data)
        except ValueError as err:
            error = "Problem deserialising data, expecting JSON.\nError: %s\nData: %s" % (
                err, json_data)
            raise EFIgyCliError(error, self.last_response)

        # Return JSON deserialised object
        return ret

    def __make_api_post(self, api_path, data=None):
        """
        Wrapper to make an API POST request, return the response and handle errors
        :return:
        """
        headers = {
            "Content-type": "application/json",
            "Accept": "application/json"}
        x = json.dumps(data)

        try:
            req = urllib2.Request(self.api_server + api_path, x, headers)
            self.last_response = urllib2.urlopen(req, cafile=self.cacert_path)
            json_data = self.last_response.read()

        # Check for errors
        except urllib2.HTTPError as err:
            error = "API HTTP error [%s] - '%s'" % (err.code, err)
            raise EFIgyCliError(error, err)

        except urllib2.URLError as err:
            error = 'Problem calling API at location %s - %s' % (
                self.api_server + api_path, err)
            raise EFIgyCliError(error, self.last_response)

        # Decode json response into an object
        try:
            ret = json.loads(json_data)
        except ValueError as err:
            error = "Problem deserialising data, expecting JSON.\nError: %s\nData: %s" % (
                err, json_data)
            raise EFIgyCliError(error, self.last_response)

        # Return JSON deserialised object
        # print "DEBUG  - %s"%(ret), type(ret)
        return ret

    def _validate_response(self, response):
        """
        Validate the response that came back from the API, return True if it's good, False if bad

        :param response: API response, Dictionary expected
        :return: True if response if valid, False if not
        """
        # Check for unexpected response - all should be JSON dicts that have
        # already been deserialised
        if not isinstance(response, types.DictionaryType):
            self.message(
                "\t\t[!] ERROR - Unexpected value returned from the API: '%s'" %
                (response))
            return False

        # Check for valid errors
        if "error" in response and "msg" in response:
            self.message(
                "\t\t[!] ERROR - %s (%s)" %
                (response["msg"], response["timestamp"]))
            return False

        # Is this a valid response message
        if "msg" in response:
            return True

        # Catch all...dictionary returned but does not contain expected keys?
        # Who know's what's going on here?!
        else:
            self.message(
                "\t\t[!] ERROR - Unexpected dictionary response returned from the API: '%s'" %
                (response))
            return False

    def _validate_json(self):
        """
        Validate the supplied json file to make sure it is json in the expected format
        :return:
        """
        # Do we find valid json?
        try:
            with open(self.batch_json_path, "rb") as fd:
                batch_json = json.loads(fd.read())

        except Exception as err:
            raise
            self.message(
                "[-] Error reading JSON batch file '%s' : '%s'" %
                (self.batch_json_path, err))
            return False

        # Does the json represent a dictionary of the expected form?
        if not isinstance(batch_json, types.DictionaryType):
            self.message(
                "[-] JSON batch file '%s' deserialises to unexpected object type '%s'" %
                (self.batch_json_path, type(batch_json)))
            return False

        # If it is a dictionary does it have the expected characteristics?
        for endpoint, sys_info in batch_json.items():

            # Endpoint should be a hostname, IP or some other string
            # identifier, difficult to validate much beyond 'string'
            if type(endpoint) not in [types.StringType, types.UnicodeType]:
                self.message(
                    "[-] Element within JSON batch file '%s' conatins unexpected object type for an endpoint element '%s'. %s : %s" %
                    (self.batch_json_path, type(endpoint), endpoint, sys_info))
                return False

            # Does the sys_info dict contain the expected keys?
            if set(sys_info.keys()).symmetric_difference(
                    set(self.json_batch_template)):
                self.message(
                    "[-] Unexpected sys_info structure within JSON batch file %s, expected keys '%s' %s : %s" %
                    (self.batch_json_path, self.json_batch_template, endpoint, sys_info))
                return False

            # Create a psuedononymised hash of the uuid using MAC addr as salt
            mac_repr = "0x" + sys_info["mac_addr"].lower().replace(":", "")
            sys_info["hashed_uuid"] = hashlib.sha256(
                mac_repr + sys_info["sys_uuid"]).hexdigest()

            # Remove both the real sys_uuid and the mac_addr from the structure so they do not get submitted to the API
            # and remain confidential to the submitter
            del sys_info["sys_uuid"]
            del sys_info["mac_addr"]

        # Set the read in json structure as the structure of system data to
        # walk and send to the API
        self.endpoints_to_check = batch_json

        self.message("[+] Batch JSON file validated")
        return True

    def __call__(self):

        try:
            self.message("\nEFIgyLite API information:")
            self.message("\tServer: %s" % (self.api_server))
            api_version = self.__make_api_get("/version")
            if api_version["version"] != VERSION:
                self.message(
                    "\n\t[!][!] EFIgyLite client version '%s' does not EFIgyLite API version '%s', bad things may happen please grab the latest version of the client from %s. [!][!]\n" %
                    (VERSION, api_version, CODE_URL))
            self.message(
                "\tAPI Version: %s\n\tUpdated On: %s\n\n" %
                (api_version["version"], api_version["updated"]))

            # Are we running in batch mode? If so validate the input file
            if self.batch_json_path:
                self.message("\n" + "=" * 50)
                self.message("\t! BATCH MODE !")
                self.message("=" * 50 + "\n")

                if not self._validate_json():
                    self.cleanup()
                    return False

            # Not batch, use info from this system to send to API for EFI
            # firmware check
            else:
                # Get the local system data to send to API to find out relevant
                # EFI firmware info
                if not self.gather_system_versions():
                    self.cleanup()
                    return False

            # For either the local gathered sys-info or for each endpoint in the supplied batch file send up the relevant
            # info to  the API to you some answers
            for endpoint, sys_info in self.endpoints_to_check.items():

                # Set the current system we are evaluating data for
                self.current_endpoint = endpoint

                self.message("-" * self.term_width)
                self.message("Endpoint: %s" % (self.current_endpoint))
                self.message(
                    "\t# Enumerated system information (This data will be sent to the API in order to determine your correct EFI version):\n")
                self.message(
                    "\tHashed SysUUID   : %s" %
                    (sys_info.get("hashed_uuid")))
                self.message(
                    "\tHardware Version : %s" %
                    (sys_info.get("hw_ver")))
                self.message(
                    "\tEFI Version      : %s" %
                    (sys_info.get("rom_ver")))
                self.message(
                    "\tSMC Version      : %s" %
                    (sys_info.get("smc_ver")))
                self.message(
                    "\tBoard-ID         : %s" %
                    (sys_info.get("board_id")))
                self.message(
                    "\tOS Version       : %s" %
                    (sys_info.get("os_ver")))
                self.message(
                    "\tBuild Number     : %s" %
                    (sys_info.get("build_num")))

                # If running in single system mode and we haven't been told to
                # be silent ask if it's OK to send data
                if not self.batch_json_path and not (self.quiet or self.yes):
                    agree = raw_input(
                        "\n[?] Do you want to continue and submit this request? [Y/N]  ").upper()
                    if agree not in ["Y", "YES"]:
                        self.message(
                            "[-] OK! Not sending request to the API. Exiting.....")
                        self.cleanup()
                        return False

                # Are we requesting server side compare of efi version only
                # rather than the whole shebang?
                if self.only_efi:
                    self.check_server_side_efi_only(sys_info)
                    continue

                # Send the datas to the API
                api_results = self.submit_system_data(sys_info)
                self.results[self.current_endpoint] = api_results

                self.message("\n\t# Results:")

                # Is this a model of mac that is getting EFI updates?
                if self.check_fw_being_updated(sys_info, api_results):
                    # If yes Are you running a Mac model that hasn't seen any FW update?
                    # Is your firmware patched to the expected level given your
                    # OS
                    self.check_fw_versions(sys_info, api_results)

                # Are running the latest build number?
                self.check_highest_build(sys_info, api_results)

                # Are you running an out of date OS minor version?
                self.check_os_up_to_date(sys_info, api_results)

            self.message("-" * self.term_width)

            # Dump json?
            self.dump_json()

            # Clean up
            self.cleanup()
            return True

        except EFIgyCliError as err:
            sys.stderr.write("%s" % (err))

    def gather_system_versions(self):
        """
        Get versions of EFI, Boot ROM, OS & Mac Device as well as the SysUUID
        :return:
        """
        # Get  Mac model ID
        self.hw_version = str(
            IORegistryEntryCreateCFProperty(
                IOServiceGetMatchingService(
                    0,
                    IOServiceMatching("IOPlatformExpertDevice")),
                "model",
                None,
                0)).replace(
            "\x00",
            "")

        if "imacpro" in self.hw_version.lower():
            # iMac Pro stores it's EFI data different due it's new architecture
            # so grab the EFI & SMC ROM versions appropriately
            raw_efi_list = []
            raw_rom_info = str(
                IORegistryEntryCreateCFProperty(
                    IORegistryEntryFromPath(
                        0,
                        "IODeviceTree:/rom"),
                    "apple-rom-info",
                    None,
                    0))
            for data in raw_rom_info.split("\n"):
                if data.strip().startswith("BIOS ID"):
                    raw_efi_list = data.split(":")[1].strip().split(".")
                    break
            else:
                self.message(
                    "[-] Could not find raw EFI data to determine EFI versions. Exiting....")
                return False

            self.efi_version = "%s.%s.%s" % (
                raw_efi_list[0], raw_efi_list[2], raw_efi_list[3])
            # Can't currently find the SMC version like this on imac pros ....
            #self.smc_version = str(IORegistryEntryCreateCFProperty(IOServiceGetMatchingService(0, IOServiceMatching("AppleSMC")), "smc-version", None, 0))
            self.smc_version = ""
        else:
            # EFI & SMC ROM versions
            self.smc_version = str(
                IORegistryEntryCreateCFProperty(
                    IOServiceGetMatchingService(
                        0,
                        IOServiceMatching("AppleSMC")),
                    "smc-version",
                    None,
                    0))
            raw_efi = str(
                IORegistryEntryCreateCFProperty(
                    IORegistryEntryFromPath(
                        0,
                        "IODeviceTree:/rom"),
                    "version",
                    None,
                    0)).replace(
                "\x00",
                "").split(".")
            self.efi_version = "%s.%s.%s" % (
                raw_efi[0], raw_efi[2], raw_efi[3])

        # Set the salt to be the MAC address of the system, using the MAC as a salt in this manner
        # helps ensure that the hashed sysuuid is pseudonymous. We don't want to know the sysuuid's
        # value, but we do want it to be unique however. The Salt value is
        # never submitted to the API
        salt = hex(getnode())
        sys_uuid = str(
            IORegistryEntryCreateCFProperty(
                IOServiceGetMatchingService(
                    0,
                    IOServiceMatching("IOPlatformExpertDevice")),
                "IOPlatformUUID",
                None,
                0)).replace(
            "\x00",
            "")
        self.h_sys_uuid = hashlib.sha256(salt + sys_uuid).hexdigest()

        # Get the Board-ID, this is how EFI files are matched to running
        # hardware - Nastee
        self.board_id = str(
            IORegistryEntryCreateCFProperty(
                IOServiceGetMatchingService(
                    0,
                    IOServiceMatching("IOPlatformExpertDevice")),
                "board-id",
                None,
                0)).replace(
            "\x00",
            "")

        # Get OS version
        self.os_version = commands.getoutput("sw_vers -productVersion")

        # Get build number
        self.build_num = commands.getoutput("sw_vers -buildVersion")

        # Carve out the major version as we use this a bunch
        #self.os_maj_ver = ".".join(self.os_version.split(".")[:2])

        # Add gathered info to the dictionary to query the API with
        self.endpoints_to_check["127.0.0.1"] = {
            "hashed_uuid": self.h_sys_uuid,
            "hw_ver": self.hw_version,
            "rom_ver": self.efi_version,
            "smc_ver": self.smc_version,
            "board_id": self.board_id,
            "os_ver": self.os_version,
            "build_num": self.build_num}

        return True

    def submit_system_data(self, data_to_submit=None):
        """
        Send the System info to the API so as the expected EFI version and other data can be
        returned relevant to this system

        :return:
        """
        endpoint = "/apple/oneshot"

        # if not data_to_submit:
        #     data_to_submit = {"hashed_uuid":self.h_sys_uuid, "hw_ver":self.hw_version, "rom_ver":self.efi_version,
        #                       "smc_ver":self.smc_version, "board_id":self.board_id, "os_ver":self.os_version, "build_num":self.build_num}

        # POST this data to the API to get relevant info back
        result_dict = self.__make_api_post(endpoint, data=data_to_submit)

        return result_dict

    def check_highest_build(self, sys_info, api_results):
        """
        Given the OS version are you running, what is the highest available build number? Are you running it?
        :return:
        """
        if not api_results.get("latest_build_number"):
            self.results[self.current_endpoint]["latest_build_number"] = self.__make_api_get(
                '/apple/latest_build_number/%s' % (".".join(sys_info.get("os_ver").split(".")[:2])))

        self.message("\n\tHighest build number check:")

        # Validate response from API
        if self._validate_response(api_results["latest_build_number"]):

            # Valid response from API - now interpret it
            if api_results["latest_build_number"][
                    "msg"] == sys_info.get("build_num"):
                self.message(
                    "\t\t[+] SUCCESS - You are running the latest build number (%s) of the OS version you have installed (%s)" %
                    (sys_info.get("build_num"), sys_info.get("os_ver")))

            elif sys_info.get("build_num")[-1].isalpha():
                self.message(
                    "\t\t[!] ATTENTION - It looks like you might be running a development OS build '%s' (%s). The EFIgy API currently only has reliable data for production OS releases." %
                    (sys_info.get("build_num"), sys_info.get("os_ver")))
            else:
                self.message(
                    "\t\t[-] ATTENTION - You are NOT running the latest release build number of your OS version (%s). Your build number is %s, the latest release build number is %s" %
                    (sys_info.get("os_ver"), sys_info.get("build_num"), api_results["latest_build_number"]["msg"]))

    def check_os_up_to_date(self, sys_info, api_results):
        """
        Given your major OS version are you running the latest minor patch?
        """
        if not api_results.get("latest_os_version"):
            self.results[self.current_endpoint]["latest_os_version"] = self.__make_api_get(
                '/apple/latest_os_version/%s' % (".".join(sys_info.get("os_ver").split(".")[:2])))

        self.message("\n\tUp-to-date OS check:")

        # Validate response from API
        if self._validate_response(api_results["latest_os_version"]):

            # Valid response from API - now interpret it
            my_os_ver_str = sys_info.get("os_ver").split(".")
            my_os_ver_num = int(
                "%s%s%s" %
                (my_os_ver_str[0],
                 my_os_ver_str[1],
                 my_os_ver_str[2]))

            api_os_ver_str = api_results["latest_os_version"]["msg"].split(".")
            api_os_ver_num = int(
                "%s%s%s" %
                (api_os_ver_str[0],
                 api_os_ver_str[1],
                 api_os_ver_str[2]))

            # if sys_info.get("os_ver") !=
            # api_results["latest_os_version"]["msg"]:
            if my_os_ver_num < api_os_ver_num:
                self.message(
                    "\t\t[-] ATTENTION - You are NOT running the most up to date version of the OS. Your OS version is %s, the latest versions is %s" %
                    (sys_info.get("os_ver"), api_results["latest_os_version"]["msg"]))

            elif my_os_ver_num > api_os_ver_num:
                self.message(
                    "\t\t[!] ATTENTION - It looks like you might be running a development OS build %s. The EFIgy API currently only has reliable data for production OS releases." %
                    (sys_info.get("os_ver")))

            else:
                self.message(
                    "\t\t[+] SUCCESS - You are running the latest major/minor/micro version of the OS you have installed (%s)" %
                    (sys_info.get("os_ver")))

    def check_fw_being_updated(self, sys_info, api_results):
        """
        Does it look like this mac model is still receiving EFI firmware updates?
        :return:
        """
        if not api_results.get("efi_updates_released"):
            # Call the API to see what the latest version of EFI you are
            # expected to be running given OS ver and mac model
            self.results[
                self.current_endpoint]["efi_updates_released"] = self.__make_api_get(
                '/apple/no_firmware_updates_released/%s' %
                (sys_info.get("hw_ver")))

        # Validate response from API
        if self._validate_response(api_results["efi_updates_released"]):

            # Check to see if this is a model that has seen any EFI firmware
            # updates
            if api_results["efi_updates_released"]["msg"] == False:
                self.message("\n\tEFI firmware version check:")
                self.message(
                    "\t\t[-]ATTENTION - Your Mac model (%s) is older than the models Apple currently provides updates for, EFIgy has no data for it." %
                    (sys_info.get("hw_ver")))
                return False
            else:
                return True

    def check_fw_versions(self, sys_info, api_results):
        """
        Compare this systems versions to the firmware table to see if FW is at latest versions
        :return:
        """
        if not api_results.get("latest_efi_version"):
            # Call the API to see what the latest version of EFI you are
            # expected to be running given OS ver and mac model
            api_results[
                self.current_endpoint]["latest_efi_version"] = self.__make_api_get(
                '/apple/latest_efi_firmware/%s/%s' %
                (sys_info.get("hw_ver"), sys_info.get("build_num")))

        self.message("\n\tEFI firmware version check:")

        # Validate response from API
        if self._validate_response(api_results["latest_efi_version"]):
            # Valid response from API - now interpret it

            # This is kind messy but it's so as we can detect newer and older firmware and message accordingly rather than just looking for 'different' versions
            # the way that EFI versions are denoted by Apple makes this more of
            # a pain thatit really needs to be quite honestly
            api_efi_str = api_results["latest_efi_version"]["msg"].split(".")
            my_efi_str = sys_info.get("rom_ver").split(".")

            api_efi_ver = int(api_efi_str[1], 16)
            api_efi_build = int(api_efi_str[2].replace("B", ""), 16)

            if all([x.isdigit() for x in my_efi_str]):
                # Newer EFI versions do not include a build number
                # or the Mac model code. The output will be something
                # like 256.0.0, whereas with the old format it would
                # be MBP133.0256.B00.
                my_efi_ver = int(my_efi_str[0], 16)
                my_efi_build = 0
            else:
                my_efi_ver = int(my_efi_str[1], 16)
                my_efi_build = int(my_efi_str[2].replace("B", ""), 16)

            if api_efi_str == my_efi_str:
                self.message(
                    "\t\t[+] SUCCESS - The EFI Firmware you are running (%s) is the expected version for the OS build you have installed (%s) on your %s" %
                    (sys_info.get("rom_ver"), sys_info.get("build_num"), sys_info.get("hw_ver")))
            elif my_efi_ver == api_efi_ver and my_efi_build == api_efi_build:
                self.message(
                    "\t\t[+] SUCCESS - The EFI Firmware you are running (%s) is the expected version for the OS build you have installed (%s) on your %s" %
                    (sys_info.get("rom_ver"), sys_info.get("build_num"), sys_info.get("hw_ver")))

            elif (my_efi_ver > api_efi_ver) or (my_efi_ver > api_efi_ver and my_efi_build > api_efi_build) or (my_efi_ver == api_efi_ver and my_efi_build > api_efi_build):
                # Looks like you're running a beta or a dev build - pretty much
                # all bets are off here as the dataset doens't cover dev builds
                # but a nicer message makes sense
                self.message(
                    "\t\t[!] ATTENTION - It looks like your EFI version (%s) is NEWER than the latest production release that is in the dataset (%s). This is most likely because you are now, or have in the past, installed a developer preview OS and as part of that you also had newer EFI firmware installed. The EFIgy API currently only has reliable data for production OS releases." %
                    (sys_info.get("rom_ver"), api_results["latest_efi_version"]["msg"]))

            else:
                self.message(
                    "\t\t[-] ATTENTION - You are running an unexpected firmware version given the model of your system (%s) and OS build you have installed (%s). Your firmware is %s, the firmware we expected to see is %s.\n" %
                    (sys_info.get("hw_ver"), sys_info.get("build_num"), sys_info.get("rom_ver"), api_results["latest_efi_version"]["msg"]))

    def check_server_side_efi_only(self, sys_info):
        """
        Just get an EFI version comparison from the server, will return one of: up2date, newer, older, model_unknown, build_unknown
        :return:
        """

        result_dict = self.__make_api_get(
            "/apple/up2date/%s/%s/%s" %
            (sys_info.get("hw_ver"),
             sys_info.get("build_num"),
             sys_info.get("rom_ver")))

        if self._validate_response(result_dict):

            if result_dict["msg"] == "up2date":
                self.message(
                    "\n\tYour firmware version %s is the expected one for a %s running build %s. Smile, today is a good day :-) " %
                    (sys_info.get("rom_ver"), sys_info.get("hw_ver"), sys_info.get("build_num")))

            elif result_dict["msg"] == "newer":
                self.message(
                    "\n\tYour firmware version %s seems newer than expected for a %s running build %s. Perhaps a beta build of macOS was installed on this system at some point?" %
                    (sys_info.get("rom_ver"), sys_info.get("hw_ver"), sys_info.get("build_num")))

            elif result_dict["msg"] == "outofdate":
                self.message(
                    "\n\tYour firmware version %s is older than expected for a %s running build %s. You should update your EFI firmware." %
                    (sys_info.get("rom_ver"), sys_info.get("hw_ver"), sys_info.get("build_num")))

            elif result_dict["msg"] == "model_unknown":
                self.message(
                    "\n\tUnknown model of Mac supplied: %s" %
                    (sys_info.get("hw_ver")))

            elif result_dict["msg"] == "build_unknown":
                self.message(
                    "\n\tUnknown OS build number supplied: %s" %
                    (sys_info.get("build_num")))

            else:
                self.message(
                    "\n\tUnexpected response from the API server: '%s'. Please file an issue at %s and include this error message" %
                    (result_dict, CODE_URL))

    def dump_json(self):
        """
        Output results in a json format which can be useful to ingest into other tools
        :return:
        """
        # JSON output not requested
        if not self.json_results:
            return

        # Are we writing to a file or stdout?
        if self.json_results == "-":
            json_results_fd = sys.stdout
        else:
            try:
                json_results_fd = open(
                    os.path.expanduser(
                        os.path.expandvars(
                            self.json_results)), "wb")

            except Exception as err:
                self.message(
                    "[-] Problem opening file '%s' to write JSON results to: %s" %
                    (self.json_results, err))
                self.message(
                    "[!] Defaulting to writing JSON results to stdout instead")
                json_results_fd = sys.stdout

        try:
            json.dump(self.results, json_results_fd)
        except Exception as err:
            self.message(
                "[-] Problem writing JSON output to %s : %s" %
                (self.json_results, err))

        if self.json_results != "-":
            self.message("[+] Written JSON results to %s" %
                         (os.path.abspath(self.json_results)))

    def cleanup(self):
        """
        Cleanup up so nothing dangles
        :return:
        """
        if self.log_fo:
            self.log_fo.close()


if __name__ == "__main__":

    # Process command line args
    parser = argparse.ArgumentParser(
        description="%s v%s. App to assess Apple EFI firmware versions." %
        (NAME, VERSION), epilog="Visit %s for more information." %
        (CODE_URL))
    parser.add_argument(
        "-l",
        "--log",
        help="Directory to log output to, log files within this directory willbe named `EFIgyLite_cli_<$timestamp>.log`")
    parser.add_argument(
        "-j",
        "--json-output",
        help="Cause results to be output in JSON format. To write to stdout provide a path of '-', else provide a path to write json results to.")
    parser.add_argument(
        "-b",
        "--batch",
        help="Batch mode. The argument is a file containing a JSON structure as detailed in the README.")
    parser.add_argument(
        "-c",
        "--cacert-path",
        help="Path to specify a cacert.pem file to use")
    parser.add_argument(
        "-s",
        "--api-server",
        default=API_URL,
        help="URL of the EFIgy API server to use including the http:// or https:// prefix, this is mainly for testing")
    parser.add_argument(
        "-o",
        "--only-efi",
        action="store_true",
        default=False,
        help="Only check the supplied EFI version against the expected version from the API. Will return if the supplied EFI version is up to date, older or newer than expected in addition to alerting on unknown hardware and OS builds.")
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Show verbose debugging output to stdout")
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Silence stdout output and don't ask to submit data to API. Use with the --log option")
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        default=False,
        help="Show client version")
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        default=False,
        help="Assume an answer of 'yes' when submitting data to the EFIgy API.")

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.version:
        print "%s %s" % (NAME, VERSION)
        sys.exit(0)

    if args.quiet:
        logger.setLevel(logging.WARNING)

    try:
        # Connect to specified EFIgy API server
        efigy_cli = EFIgyCli(
            args.api_server,
            quiet=args.quiet,
            debug=args.debug,
            log_path=args.log,
            json_results=args.json_output,
            batch_json_path=args.batch,
            cacert_path=args.cacert_path,
            only_efi=args.only_efi,
            yes=args.yes)
        efigy_cli()

        sys.exit(0)

    except Exception as err:
        print "[-] Fatal error in %s. Exiting....." % (NAME)
        if args.debug:
            import traceback
            print "\nError:\n\t%s" % (err)
            print "\n%s" % (traceback.format_exc())

        sys.exit(-1)
