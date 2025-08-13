import time

import chardet
from impacket import nmb
from impacket.examples.utils import parse_target
from impacket.smbconnection import FILE_READ_DATA, SMBConnection

from util.logging import logger
from memoization import cached

class SMBHandler:
    def __init__(self):
        self.address = ""
        self.domain = ""
        self.username = ""
        self.password = ""
        self.lmhash = ""
        self.nthash = ""
        self.shareHandle = None
        self.target = ""
        self.target_ip = ""
        self.dc_ip = ""
        self.kerb = False

    def authenticate_impacket(
        self, target, dc_ip, hashes, target_ip, kerb=False
    ):
        attempt = 1
        max_attempt = 3

        while attempt <= max_attempt:
            try:
                domain, username, password, address = parse_target(target)
                self.address = address
                self.domain = domain
                self.username = username
                self.dc_ip = dc_ip
                self.password = password
    
                self.target = target
                self.target_ip = target_ip
                self.kerb = kerb
                self.hashes = hashes
                if target_ip is None:
                    self.target_ip = address
                if hashes is not None:
                    self.lmhash, self.nthash = hashes.split(":")
                else:
                    self.lmhash = ""
                    self.nthash = ""
                self.smbClient = SMBConnection(
                    self.address, self.target_ip, sess_port=445
                )
                if kerb is True:
                    self.smbClient.kerberosLogin(
                        username,
                        password,
                        domain,
                        self.lmhash,
                        self.nthash,
                        dc_ip,
                    )
                else:
                    self.smbClient.login(
                        username, password, domain, self.lmhash, self.nthash
                    )
                self.shareHandle = self.smbClient.connectTree("SCCMContentLib$")

                return address
            except Exception as e:
                logger.error(f"Error authenticating {e}", exc_info=True)
                attempt += 1
                time.sleep(attempt * 1)

    def reauthenticate_impacket(self):
        attempt = 1
        max_attempt = 10

        while attempt <= max_attempt:
            try:
                self.authenticate_impacket(
                    self.target,
                    self.dc_ip,
                    self.hashes,
                    self.target_ip,
                    self.kerb,
                )
                break
            except Exception as e:
                logger.warning(
                    f"Error reauthenticate_impacket attempt {attempt}/{max_attempt} Type:{type(e).__name__}"
                )
                attempt = attempt + 1
                time.sleep(attempt * 2)

    def list_folder(self, path, returnAccessDenied=False):
        """
        returns all files and folders in path
        """
        folderList = []
        fileList = []
        splitted = path.split("\\")
        address = splitted[2]
        path = "\\".join(splitted[4:])

        attempt = 1
        max_attempt = 2

        while attempt <= max_attempt:
            try:
                objects = self.smbClient.listPath("SCCMContentLib$", path + "\\*")
                for i in objects:
                    if (
                        i._SharedFile__filesize == 0
                        and i._SharedFile__shortname not in (".", "..")
                    ):
                        folder = (
                            "\\\\"
                            + address
                            + "\\SCCMContentLib$\\"
                            + path
                            + "\\"
                            + i._SharedFile__shortname
                        )
                        folderList.append(folder)
                    if i._SharedFile__filesize != 0:
                        file = (
                            "\\\\"
                            + address
                            + "\\SCCMContentLib$\\"
                            + path
                            + "\\"
                            + i._SharedFile__shortname
                        )
                        fileList.append(file)
                break
            except Exception as e:
                if "Access Denied" in str(e):
                    logger.warning(
                        f"Access Denied while listing folder {path}. Skipping. Error: {e}"
                    )
                    if returnAccessDenied:
                        return folderList, fileList, "Access Denied"
                    return folderList, fileList
                else:
                    logger.warning(
                        f"list_folder error attempt {attempt}/{max_attempt}: {e} Type:{type(e).__name__}"
                    )
                    attempt = attempt + 1
                    time.sleep(attempt * 1)
                    if e is ConnectionError:
                        self.reauthenticate_impacket()
        if returnAccessDenied:
            return folderList, fileList, None
        return folderList, fileList

    def read_file(self, path) -> str | None:
        assert self.smbClient

        attempt = 1
        max_attempt = 5
        fullPath = path
        fileID = None
        while attempt <= max_attempt:
            try:
                if "SCCMContentLib" in path:
                    path = "\\".join(path.split("\\")[4:])
                
                fileID = self.smbClient.openFile(self.shareHandle, path, FILE_READ_DATA)
                data = self.smbClient.readFile(self.shareHandle, fileID)
                chardet_result = chardet.detect(data)
                
                if (
                    chardet_result is not None
                    and chardet_result["encoding"] is not None
                ):
                    output = data.decode(chardet_result["encoding"])
                else:
                    output = str(data)
                    logger.debug(f"Done reading {fullPath}")

                    return output
                logger.debug(f"Done reading {fullPath}")
                return output
            except nmb.NetBIOSTimeout as e:
                logger.info(
                    f"read_file error attempt {fullPath} {attempt}/{max_attempt}: {e} Type:{type(e).__name__}"
                )
                attempt += 1
                time.sleep(attempt * 1)
                self.reauthenticate_impacket()
            except UnicodeDecodeError as e:
                logger.info(
                    f"Error reading file {fullPath} {e} Type:{type(e).__name__}"
                )
                return None
            except AttributeError:
                logger.info(
                    f"read_file error attempt {fullPath} {attempt}/{max_attempt}:",
                    exc_info=True,
                )
                attempt += 1
                time.sleep(attempt * 1)
                self.reauthenticate_impacket()
            except Exception as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    logger.warning(
                        f"File {fullPath} not found. Skipping. Error: {e}"
                    )
                    return None
                logger.info(
                    f"Error reading file attempt {attempt}/{max_attempt} {fullPath}: {e}",
                    exc_info=True,
                )
                attempt += 1
                time.sleep(attempt * 2)
                if e is ConnectionError:
                    self.reauthenticate_impacket()

            finally:
                try:
                    if fileID is not None:
                        self.smbClient.closeFile(self.shareHandle, fileID)
                except Exception:
                    logger.warning(f"Error closing file {fullPath}")
        return None

    def download_file(self, srcPath, tgtPath):
        attempt = 1
        max_attempt = 5
        path = srcPath
        while attempt <= max_attempt:
            try:
                if "SCCMContentLib" in srcPath:
                    path = "\\".join(srcPath.split("\\")[4:])
                with open(tgtPath, "wb") as wf:
                    self.smbClient.getFile("SCCMContentLib$", path, wf.write)
                    return
            except Exception as e:
                logger.info(
                    f"Error trying to download file {attempt}/{max_attempt} {path} : {e}"
                )
                attempt += 1
                time.sleep(attempt * 2)
                if e is ConnectionError:
                    self.reauthenticate_impacket()
        logger.error(f"Couldn't download file {path} to {tgtPath}.")

    def list_directory_recursive_key(path, config, smbClient, depth=0, depthLimit=15):
        return path

    @cached(custom_key_maker=list_directory_recursive_key, ttl=60, max_size=512)
    def list_directory_recursive(path, config, smbClient, depth=0, depthLimit=15):
        """
        recursivly lists a folder/filestructure and returns all file paths in a list
        path = absolute basepath
        config = parsed config yml
        depth = so the recursion knows how deep it is
        depthLimit = stop when this depth is reached starting from the basepath
        """

        if depth == 0:
            logger.debug(f"listing {path}")
            depth += 1
        ls = []
        if depth >= depthLimit:
            logger.warning(
                f"Canceled listing directory because depth limit({depthLimit}) was reached. Path: {path}"
            )
            return ls
        try:
            folderList, fileList = smbClient.list_folder(path)

            for file in fileList:
                ls.append(f"{file}")
            for folder in folderList:
                ls.extend(SMBHandler.list_directory_recursive(f"{folder}", config, smbClient, depth))
        except Exception as e:
            logger.warning(f"list_directory_recursive Exception: {e}")
        return ls
