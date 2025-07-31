import yaml
import re
from util.logging import logger
from memoization import cached

@cached(ttl=120)
def is_extension_whitelisted(extension, whitelisted_extensions):
    """
    checks if the extension is whitelisted or should be ignored
    filename = name of the file
    whitelisted_extensions = list of whitelisted extensions
    """

    try:
        if extension.lower() not in whitelisted_extensions:
            return False
        return True
    except Exception as ex:
        logger.debug(f"is_extension_whitelisted exception: {ex}")


def is_filename_ignored(fileName, config):
    """
    checks if the filename should be ignored according to the config
    filename = name of the file
    config = parsed config yml
    """
    isIgnored = False
    skipPackage = False

    for entry, skip in config["filenames"]["ignoreDict"].items():
        if entry.lower() == fileName.lower():
            isIgnored = True
            if skip:
                skipPackage = True
            return isIgnored, skipPackage
    return isIgnored, skipPackage

def read_config(path):
    """
    parses the config yml file, adds some dicts and returns the config
    path = path to config yml file
    """
    with open(path) as stream:
        try:
            config = yaml.safe_load(stream)

            logger.warning("whitelisted extensions: %s" % config["extensions"])
            logger.warning("ignored filenames: %s" % config["filenames"]["ignore"])

            regex_patterns = [line.strip() for line in config["patterns"]]
            config["patterns_compiled"] = [
                re.compile(pattern) for pattern in regex_patterns
            ]
            logger.warning("Patterns: %s" % config["patterns_compiled"])

            config["filenames"]["ignoreDict"] = {}
            for ignoreEntry in config["filenames"]["ignore"]:
                if "skipFolder" not in ignoreEntry:
                    ignoreEntry["skipFolder"] = False
                config["filenames"]["ignoreDict"][ignoreEntry["name"]] = ignoreEntry[
                    "skipFolder"
                ]

            config["filenames"]["reportDict"] = {}
            for reportEntry in config["filenames"]["report"]:
                if "description" not in reportEntry:
                    reportEntry["description"] = None
                config["filenames"]["reportDict"][reportEntry["name"]] = reportEntry[
                    "description"
                ]

            config["matches"]["ignoreDict"] = dict(
                zip(config["matches"]["ignore"], config["matches"]["ignore"])
            )
            config["filehashes"]["ignoreDict"] = dict(
                zip(config["filehashes"]["ignore"], config["filehashes"]["ignore"])
            )

        except yaml.YAMLError:
            logger.error("read config error:", exc_info=True)
            exit(1)
        return config
    
def filter_packages(entries, list_packages):
    if "," in list_packages:
        list_packages = list_packages.split(",")

    filtered_entries = []
    for entry in entries:
        if isinstance(list_packages, list):
            for package in list_packages:
                if package in entry:
                    filtered_entries.append(entry)
        else:
            if list_packages in entry:
                filtered_entries.append(entry)
    return filtered_entries