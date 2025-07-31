import configparser
import time

from util.logging import logger

class pkgLibEntry:
    def __init__(self, PackageListEntry, sccmserver):
        self.path = PackageListEntry
        self.sccmserver = sccmserver
        self.created = time.time()
        if PackageListEntry is not None:
            self.name = PackageListEntry.split("\\")[-1].replace(".INI", "")
            logger.error(f"{self.name} started")
        self.packages = []
        
    @classmethod
    def from_manual(cls):
        return cls(PackageListEntry=None, sccmserver=None)

    def read_config(self, smbClient):
        try:
            self.config = configparser.ConfigParser()
            file_content = smbClient.read_file(self.path)
            self.config.read_string(file_content)
            if "Packages" in self.config:
                packages = self.config["Packages"]
                for key in packages:
                    self.packages.append(dataLibEntry(key, self.sccmserver))
        except Exception as e:
            logger.warning(f"read config error: {e}")

class dataLibEntry:
    def __init__(self, name, sccmserver):
        self.name = name
        self.path = f"\\\\{sccmserver}\\SccmContentLib$\\dataLib\\{name}"
