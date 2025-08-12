import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
import concurrent.futures
import queue
from threading import Thread
from tqdm import tqdm

from util.logging import handler, logger
from util.result import *
from util.SCCMContentLib import pkgLibEntry
from util.smbhandler import SMBHandler
from util.tqdmWriteProxy import tqdmWriteProxy
from memoization import cached
import util.report as report
import util.config as ConfigHelper

import tracemalloc

RED = "\033[91m"
ENDC = "\033[0m"  # Reset color

def download_package(packageID, options, config):
    """
    Downloads a Single Package from a target SCCM server.
    packageID = e.g. ZAS00CFD
    target = FQDN or IP
    config = parsed config yml
    """
    smbClient = None
    try:
        smbClient = SMBHandler()
        smbClient.authenticate_impacket(
            target=options.target,
            dc_ip=options.dc_ip,
            hashes=options.hashes,
            target_ip=options.target_ip
        )
        entry = pkgLibEntry.from_manual()
        entry.path = (
            f"\\\\{smbClient.target_ip}\\SCCMContentLib$\\PkgLib\\{packageID}.INI"
        )
        entry.sccmserver = smbClient.target_ip
        entry.packages = []
        entry.name = packageID
        entry.read_config(smbClient)
        if len(entry.packages) == 0:
            logger.error(f"package {packageID} not found.")
            exit(0)
        logger.error(f"Downloading {len(entry.packages)} dataLibs from package {packageID}")
        for dataLib in entry.packages:
            logger.error(f"Listing files of datalib package {dataLib.name}")
            fileList = SMBHandler.list_directory_recursive(dataLib.path, config, smbClient)

            total_files = len(fileList)
            if total_files < options.workers:
                options.workers = total_files
            avg_files_per_worker = total_files // options.workers
            remaining_files = total_files % options.workers

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=options.workers
            ) as executor:
                futures = []
                with tqdm(
                    total=len(entry.packages), desc=f"Downloading dataLib: {dataLib.name}"
                ) as pbar:
                    handler.setStream(tqdmWriteProxy.get())
                    for start in range(0, total_files, avg_files_per_worker):
                        if start + avg_files_per_worker <= total_files:
                            futures.append(
                                executor.submit(
                                    download_dataLib_file,
                                    fileList[start : start + avg_files_per_worker],
                                    entry,
                                    config,
                                    options,
                                )
                            )
                    if remaining_files > 0:
                        remaining_fileList = fileList[total_files - remaining_files :]
                        futures.append(
                            executor.submit(
                                download_dataLib_file,
                                remaining_fileList,
                                entry,
                                config,
                                options,
                            )
                        )
                    for future in concurrent.futures.as_completed(futures):
                        pbar.update(avg_files_per_worker)
                handler.setStream(sys.stdout)

    except Exception as e:
        logger.error(
            f"download_package error: {e} type: {type(e).__name__}", exc_info=True
        )
    finally:
        if smbClient is not None and smbClient.smbClient is not None:
            smbClient.smbClient.close()

def download_dataLib_file(filePaths, entry, config, options):
    """
    Downloads a single file from a SCCM server.
    filePath = e.g. ZAS00CFD
    entry = pkgLibEntry
    config = parsed config yml
    """
    smbClient = SMBHandler()
    smbClient.authenticate_impacket(
        target=options.target,
        dc_ip=options.dc_ip,
        hashes=options.hashes,
        target_ip=options.target_ip
    )
    for filePath in filePaths:
        hash = get_hash(filePath, config, smbClient)
        if hash is not None:
            dataFilePath = (
                f"\\\\{entry.sccmserver}\\SCCMContentLib$\\FileLib\\{hash[:4]}\\{hash}"
            )
            short_path = filePath.split("\\")[5:]

            local_relative_path = (
                entry.name + "/" + ("/".join(short_path).replace(".INI", ""))
            )
            short_dir_path = "/".join(local_relative_path.split("/")[:-1])
            path = Path(short_dir_path, "")
            try:
                path.mkdir(parents=True, exist_ok=True)
                smbClient.download_file(dataFilePath, local_relative_path)
            except Exception as e:
                logger.error(
                    f"download datalib file error: {e} type: {type(e).__name__} path:{short_dir_path}",
                    exc_info=True,
                )
                exit(1)

def get_hash(path, config, smbClient):
    """
    retrieves the hash of a dataLib .ini file
    path = absolute path to the .ini file
    config = parsed config yml
    """
    try:
        logger.debug(f"retrieving hash of file: {path}")
        content = smbClient.read_file(path)
        for t in content.split("\n"):
            if t.startswith("Hash="):
                hash_value = t.split("=")[-1].strip()
                return hash_value

    except Exception as e:
        logger.warning(
            f"Retrieving hash failed: {e} type: {type(e).__name__} path={path}"
        )
        return None

def get_fileinfo(path, config, smbClient: SMBHandler) -> tuple[str, str, str]:
    """
    retrieves the time_modified,hash and filesize of a dataLib .ini file
    path = absolute path to the .ini file
    config = parsed config yml
    """
    try:
        logger.debug(f"retrieving info from file: {path}")
        time_readfile = time.time()
        content = smbClient.read_file(path)
        timeToRead = int(time.time() - time_readfile)
        if timeToRead > 0:
            logger.debug(f"{RED}reading {path} Done. Took {timeToRead} seconds{ENDC}")
        else:
            logger.debug(f"reading {path} Done. Took {timeToRead} seconds")
        if content is None:
            return "", "", ""
        hash_value: str = ""
        timemodified: str = ""
        filesize_kb: str = ""

        for t in content.split("\n"):
            if t.startswith("Hash="):
                hash_value = t.split("=")[-1].strip()

            if t.startswith("TimeModified="):
                timemodified = t.split("=")[-1].strip()
                filetime_s = int(timemodified) / 1e7
                filetime_base_date = datetime(1601, 1, 1)
                converted_datetime = filetime_base_date + timedelta(seconds=filetime_s)
                timemodified = str(converted_datetime)

            if t.startswith("Size="):
                filesize_kb = t.split("=")[-1].strip()

        return hash_value, timemodified, filesize_kb

    except Exception as e:
        logger.warning(f"Retrieving fileinfo failed: {e} {path}", exc_info=True)
        return "", "", ""
    
def check_patterns_key(
    filePath, filename, timemodified, filesize, config, smbClient, hash
):
    return hash

@cached(custom_key_maker=check_patterns_key, max_size=1000, ttl=1200)
def check_patterns(filePath, filename, timemodified, filesize, config, smbClient, hash):
    """
    checks all regex patterns from the config against the files content
    filePath = absolute basepath
    filename = name of the file to include in the result
    config = parsed config yml
    """
    logger.debug(
        f"Checking patterns for {filePath}. Filesize: {filesize}KB. Filename: {filename}"
    )
    results_list = []

    try:
        file_content = smbClient.read_file(filePath)
        if file_content is None:
            return results_list
        time_readfile = time.time()
        for pattern in config["patterns_compiled"]:
            readpattern = time.time()
            result = pattern.finditer(file_content)

            if result:
                for res in result:
                    result_obj = Result(
                        filename, filePath, pattern.pattern, res, timemodified, filesize
                    )
                    if not config["matches"]["ignoreDict"].get(
                        result_obj.matched_content
                    ):
                        result_obj.matched_content_expanded = (
                            result_obj.get_expanded_result(file_content, 3, 3)
                        )
                        result_obj.matched_content_expanded = (
                            result_obj.matched_content_expanded.replace(
                                "\n", "\n\t"
                            )
                        )
                        extended = result_obj.matched_content_expanded.replace("\r","")
                        logger.warning(
                            f"{RED}\n==========\nMatched:\n\t{result_obj.matched_content}\nExpanded:\n\t{extended}\npattern: {pattern.pattern}\nfilename: {filename} \npath: {filePath}\n=========={ENDC}"
                        )
                        results_list.append(result_obj)

        timeToRead = int(time.time() - time_readfile)
        logger.debug(
            f"{RED}Checking file {filePath} Done. Took {timeToRead} seconds{ENDC}"
        )
    except Exception as e:
        logger.warning(f"check_patterns exception: {e}", exc_info=True)

    if len(results_list) > 100:
        return results_list[:100]
    return results_list

def check_filename_key(
    filename, filepath, timemodified, filesize, config, smbClient, hash
):
    return hash

@cached(custom_key_maker=check_filename_key, ttl=120, max_size=1000)
def check_filename(filename, filepath, timemodified, filesize, config, smbClient, hash):
    """
    checks if filename should be reported according to config
    filename = name of the file to include in the result
    config = parsed config yml
    """
    results_list = []

    try:
        if filename in config["filenames"]["reportDict"]:
            description = config["filenames"]["reportDict"][filename]
            dataFilePath = f"\\\\{smbClient.target_ip}\\SCCMContentLib$\\FileLib\\{hash[:4]}\\{hash}"
            file_content = smbClient.read_file(dataFilePath)
            file_content = file_content[:500].replace("\n", "\n\t\t\t")
            logger.warning(
                f"{RED}==========\nFilename matched: {filename} \n\tdataLib: {filepath} \n\tfile: {dataFilePath} \n\tReason={description} \n\ttimemodifiedl={timemodified}\n\tfilesize_KB={str(filesize)} \n\tContent={file_content}\n=========={ENDC}"
            )
            results_list.append(
                Result(
                    filename,
                    dataFilePath,
                    f"Reported based on filename. \n\t\t\tReason={description} \n\t\t\tDataLib={filepath}\n\t\t\tContent={file_content}",
                    config["filenames"]["reportDict"][filename],
                    timemodified,
                    filesize,
                )
            )

    except Exception as e:
        logger.warning(f"check_filename exception: {e}", exc_info=True)
    if len(results_list) > 100:
        return results_list[:100]
    return results_list

def parse_pkgLib(PackageListEntry, sccmHost, config, smbClientThread):
    """
    parses a packageLib, further checks are implemented in parse_dataLib
    PackageListEntry = SMBDirEntry returned from SMBHandler.list_folder
    sccmHost = target sccm hosts FQDN or IP
    config = parsed config yml
    """
    try:
        entry = pkgLibEntry(PackageListEntry, sccmHost)

        entry.read_config(smbClientThread)
        name = PackageListEntry.split("\\")[-1]
        path = PackageListEntry

        if len(entry.packages) >= 30:
            logger.info(
                f"Skipped {entry.name} because it has {len(entry.packages)} packages. (>=50)"
            )
            return None

        all_dataLib_results = []
        logger.info(f"reading dataLib {entry.name}")
        for package in entry.packages:
            dataLib_results = parse_dataLib(
                package, entry.name, config, smbClientThread
            )
            if dataLib_results is not None:
                all_dataLib_results.append(dataLib_results)
        package_duration = int(time.time() - entry.created)
        logger.warning(f"{entry.name} Done. Took {package_duration} seconds")

        if len(all_dataLib_results) >= 1:
            logger.warning(f"{name} {len(all_dataLib_results)} results")

            packageResult = PackageResult(name, path, all_dataLib_results, sccmHost)
            return packageResult

    except Exception as e:
        logger.warning(f"parse_pkgLib exception: {e} type: {type(e).__name__}")
    return None

def parse_dataLib(dataLib, pkgLib, config, smbClient):
    """
    parses a dataLib, checks if the file/path should be skipped/ignored and then checks for regex matches
    PackageLib = single SMBDirEntry returned from SMBHandler.list_folder
    config = parsed config yml
    """
    try:
        fileList = SMBHandler.list_directory_recursive(dataLib.path, config, smbClient)
        if len(fileList) == 0:
            folderList, fileList, errorMsg = smbClient.list_folder(dataLib.path,returnAccessDenied=True)
            if errorMsg == "Access Denied":
                logger.error(f"{dataLib.name} does not exist or access denied: {dataLib.path}")
                try:
                    with open(f"denied_datalibs_{smbClient.address}.txt", "a") as f:
                        f.write(f"{dataLib.name}\n")
                except Exception as ex:
                    logger.debug(f"Error writing denied dataLib to file: {ex}", exc_info=True)
        if config.get("inventory"):
            try:
                with open(config.get("inventory_file"), "a") as f:
                    for filePath in fileList:
                        hash, timemodified, filesize = get_fileinfo(filePath, config, smbClient)
                        f.write(f"{pkgLib};{filePath};{timemodified};{filesize},\\\\{smbClient.address}\\SCCMContentLib$\\FileLib\\{hash[:4]}\\{hash}\n")
                return None
            except Exception as ex:
                logger.debug(f"Error writing filenames to file: {ex}", exc_info=True)

        dataLib_results = []
        for filePath in fileList:
            fileName = filePath.split("\\")[-1]
            hash, timemodified, filesize = get_fileinfo(filePath, config, smbClient)

            results = check_filename(
                fileName, filePath, timemodified, str(filesize), config, smbClient, hash
            )
            if len(results) > 0:
                dataLib_results.extend(results)

            if "filesize" not in config:
                extension = filePath.split("\\")[-1].split(".")[-2]
                if filePath.count(".") >= 3 and not ConfigHelper.is_extension_whitelisted(
                    extension, config["extensions"]
                ):  # filename allways ends with .INI
                    # files with no extension are atm always skipped
                    logger.debug(f"{fileName} skipped due to extension")
                    continue
            else:
                if int(filesize) > 1000:
                    # logger.info(f"{pkgLib} {fileName} skipped {filesize}>1000. {dataFilePath}")
                    continue
                else:
                    logger.info(
                        f"{pkgLib} checking {fileName} {filesize}<1000. {filePath}"
                    )

            isIgnored, skipPackage = ConfigHelper.is_filename_ignored(fileName, config)
            if skipPackage:
                logger.info(f"{dataLib.name} skipped due to ignored file {fileName}")
                return None
            if isIgnored:
                logger.debug(f"ignored file {fileName}")
                continue

            dataFilePath = f"\\\\{smbClient.target_ip}\\SCCMContentLib$\\FileLib\\{hash[:4]}\\{hash}"
            if hash == "":
                continue
            if config["filehashes"]["ignoreDict"].get(hash):
                logger.debug(
                    f"{fileName} ignored because hash is on ignorelist: {hash}"
                )
                continue

            logger.debug(f"analysing {fileName}")

            results = check_patterns(
                dataFilePath,
                fileName,
                timemodified,
                str(filesize),
                config,
                smbClient,
                hash,
            )

            if len(results) > 0:
                dataLib_results.extend(results)
            elif config.get("saveHashes"):
                try:
                    with open("hashes.txt", "a") as f:
                        f.write(f"{hash}\n")
                except Exception as ex:
                    logger.debug(f"Error writing hash to file: {ex}", exc_info=True)

        if len(dataLib_results) > 100:
            return DataLibResult(dataLib.name, dataLib.path, dataLib_results[:100])
        if len(dataLib_results) > 0:
            return DataLibResult(dataLib.name, dataLib.path, dataLib_results)

        del fileList

    except Exception as ex:
        logger.warning(f"parse_dataLib exception: {ex}", exc_info=True)

    return None

def parse_SCCM(options, config):
    """
    check a single sccm server for results according to config file
    options = parsed argparse arguments
    config = parsed config yml
    """
    if options.debug:
        tracemalloc.start()

    # listener to allow increasing verbositylevel. Press v and hit enter to increase
    increase_verbosity_listener = Thread(target=listen_for_input, daemon=True)
    increase_verbosity_listener.start()

    # futures = []
    # all_results = []
    smbClient = SMBHandler()
    smbClient.authenticate_impacket(
        target=options.target,
        hashes=options.hashes,
        dc_ip=options.dc_ip,
        target_ip=options.target_ip
    )
    logger.info(f"Listing \\\\{smbClient.target_ip}\\SCCMContentLib$\\PkgLib")
    folderList, fileList = smbClient.list_folder(
        f"\\\\{smbClient.target_ip}\\SCCMContentLib$\\PkgLib"
    )

    if options.packages is not None:
        fileList = ConfigHelper.filter_packages(fileList, options.packages)

    total_entries = len(fileList)
    if options.limit:
        if total_entries > options.limit:
            total_entries = options.limit
            fileList = fileList[: options.limit]
    total_files = total_entries

    file_queue = queue.Queue()
    progress_queue = queue.Queue()
    report_queue = queue.Queue()
    for file in fileList:
        file_queue.put(file)

    with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as executor:
        executor.submit(report_progress, progress_queue, total_files)
        for _ in range(options.workers):
            executor.submit(
                worker, file_queue, progress_queue, report_queue, options, config
            )

    file_queue.join()
    progress_queue.join()

    queue_length = report_queue.qsize()
    if queue_length > 0:
        logger.warning(f"{queue_length} results")
        queue_list = []
        while not report_queue.empty():
            queue_list.append(report_queue.get())
        report.save_results_to_json(queue_list, options.outputfile)

    logger.warning("skipped extensions:")

def report_progress(progress_queue, total_files):
    with tqdm(total=total_files, desc="Processing PkgLib") as pbar:
        handler.setStream(tqdmWriteProxy.get())
        processed_files = 0
        while processed_files < total_files:
            progress_queue.get()
            processed_files += 1
            pbar.update(1)
            progress_queue.task_done()

    handler.setStream(sys.stdout)

def listen_for_input():
    """
    listener to be able to increase verbosity while running the script
    """
    import readchar

    while True:
        try:
            user_input = readchar.readkey()
            logger.error(f"input: {user_input}")
            global debugLvl
            if user_input.lower() == "v":
                if debugLvl < 3:
                    debugLvl += 1
                logger.error(f"debugLvl: {debugLvl}")

            if user_input.lower() == "0":
                debugLvl = 0
                logger.error(f"debugLvl: {debugLvl}")

            if user_input.lower() == "1":
                debugLvl = 1
                logger.error(f"debugLvl: {debugLvl}")

            if user_input.lower() == "2":
                debugLvl = 2
                logger.error(f"debugLvl: {debugLvl}")

            if user_input.lower() == "3":
                debugLvl = 3
                logger.error(f"debugLvl: {debugLvl}")

            if user_input.lower() == "e":
                exit(1)

            logger.setLevel(40 - 10 * debugLvl)
        except Exception:
            logger.error("Error in inputlistener", exc_info=True)
            pass

def worker(file_queue, progress_queue, report_queue, options, config):
    smbClientThread = SMBHandler()
    smbClientThread.authenticate_impacket(
        target=options.target,
        dc_ip=options.dc_ip,
        hashes=options.hashes,
        target_ip=options.target_ip
    )

    while not file_queue.empty():
        try:
            file = file_queue.get_nowait()
        except queue.Empty:
            break
        result =  parse_pkgLib(file, smbClientThread.target_ip, config, smbClientThread)
        progress_queue.put(file)
        if result is not None:
            report_queue.put(result)
        file_queue.task_done()
    smbClientThread.smbClient.close()

