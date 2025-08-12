#!/usr/bin/env python3

import argparse
import sys
from datetime import datetime

from impacket.examples.utils import parse_target

from util.logging import logger
import util.SLAPFunctions as SLAPFunctions
import util.SLAPUnsecureDatalibs as SLAPUnsecureDatalibs
import util.config as configHelper
from os import path as os_path

debugLvl = 0

def main():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="SCCM SLAP (SCCM Secret Locator and Package Analyzer)\n\n",
        epilog="Example usage:"
                "\n\t./SLAP.py user:pass@FQDN -config config.yml -outputfile out.json"
                "\n\t./SLAP.py user:pass@FQDN -download ZAS123456"
                "\n\t./SLAP.py user:pass@FQDN -packages ZAS123456,ZAS654321"
                "\n\t./SLAP.py user:pass@FQDN -inventory"
                "\n\t./SLAP.py user@FQDN -config config.yml -outputfile out.json -hashes LMHASH:NTHASH",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "-config", default="config.yml", action="store", help="Config as YAML file"
    )
    parser.add_argument(
        "-outputfile",
        default="out.json",
        action="store",
        help="Output file to log smbclient actions in",
    )
    parser.add_argument(
        "-v", action="store_true", help="Turn verbose output ON level 1. (PkgLib Level)"
    )
    parser.add_argument(
        "-vv",
        action="store_true",
        help="Turn verbose output ON level 2. (DataLib Level)",
    )
    parser.add_argument(
        "-vvv",
        action="store_true",
        help="Turn verbose output ON level 3. (FileLib Level)",
    )
    parser.add_argument(
        "-debug",
        action="store_true",
        help="Turn DEBUG on to analyze cache and memory usage.",
    )
    parser.add_argument(
        "-limit", action="store", help="Only parse x amount of packages", type=int
    )
    parser.add_argument(
        "-download",
        action="store",
        help="Download all files of packageID into current working directory",
    )
    parser.add_argument(
        "-packages",
        action="store",
        help="Comma seperated string of packages that should be scanned e.g. ZAS03801,ZAS04845",
    )
    parser.add_argument(
        "-filesize",
        action="store_true",
        help="Testing: Just skip large files. No extension whitelisting.",
    )
    parser.add_argument(
        "-saveHashes",
        action="store_true",
        help="Adds hashes with no findings to a file in current working directory.",
    )
    parser.add_argument(
        "-inventory",
        action="store_true",
        help="Creates inventory csv in current working directory. If set, no patterns are checked. (PackageID;dataLib_FileName;timemodified;filesize_KB;fileLib_path)",
    )
    parser.add_argument(
        "-workers",
        default=100,
        action="store",
        help="Number of workers for parallel tasks",
        type=int,
    )
    parser.add_argument(
        "-unsecureDatalibs",
        action="store_true",
        help="reads denied_datalibs_<address>.txt and checks patterns of config in fileLib-files with reference to secured datalibs.",
    )

    impacket = parser.add_argument_group("impacket")

    impacket.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )

    impacket.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )
    impacket.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target machine. If omitted it will use whatever was specified as target. "
        "This is useful when target is the NetBIOS name and you cannot resolve it",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1 or options.target is None:
        parser.print_help()
        sys.exit(1)

    global debugLvl
    debugLvl = 0
    if options.v:
        debugLvl = 1
    if options.vv:
        debugLvl = 2
    if options.vvv:
        debugLvl = 3
    logger.setLevel(40 - 10 * debugLvl)
    logger.error(f"Debuglvl: {debugLvl}")

    if options.workers < 2:
        logger.error("Number of workers must be at least 2.")
        sys.exit(1)

    config = configHelper.read_config(options.config)
    if options.saveHashes:
        config["saveHashes"] = True
    
    domain, username, password, address = parse_target(options.target)
    if options.inventory:
        config["inventory"] = True
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S_%f')
        config["inventory_file"] = f"inventory_{address}_{timestamp}.csv"
        try:
            with open(config["inventory_file"], 'w') as file:
                file.write("PackageID;dataLib_FileName;timemodified;filesize_KB;fileLib\n")
        except Exception as ex:
            logger.error(f"Error creating inventory file: {ex}", exc_info=True)
            exit(1)

    if options.filesize:
        config["filesize"] = 10000
    try:
        if options.download is not None:
            SLAPFunctions.download_package(options.download, options, config)
            logger.error(f"Check folder {options.download} in current working directory.")
        elif options.unsecureDatalibs:
            SLAPUnsecureDatalibs.unsecure_datalibs(options, config)
        else:
            SLAPFunctions.parse_SCCM(options, config)
            if os_path.exists(options.outputfile):
                logger.error(f"Output file {options.outputfile} created.")
            if os_path.exists(f"denied_datalibs_{address}.txt"):
                logger.error(f"denied_datalibs_{address}.json was created. Run again with -unsecureDatalibs to check protected datalib files.")
                
    except Exception:
        logger.error("", exc_info=True)
        if Exception is KeyboardInterrupt:
            raise

if __name__ == "__main__":
    main()