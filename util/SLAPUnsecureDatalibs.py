from util.tqdmWriteProxy import tqdmWriteProxy
from util.smbhandler import SMBHandler
from util.logging import handler, logger
from util.SLAPFunctions import check_patterns
from util.result import DataLibResult
import util.report
import sys
import queue
import concurrent.futures
from tqdm import tqdm

def worker(folder_queue, progress_queue, report_queue, options, config):
    """
    Worker function to process folders in the fileLib directory, check for dataLib references and report results.

    Args:
        folder_queue (queue.Queue): Queue containing folders to process.
        progress_queue (queue.Queue): Queue to report progress.
        report_queue (queue.Queue): Queue to collect results for reporting.
        options (argparse.Namespace): Command line options.
        config (dict): Configuration dictionary.
    """
    smbClient = SMBHandler()
    smbClient.authenticate_impacket(
        target=options.target,
        dc_ip=options.dc_ip,
        hashes=options.hashes,
        target_ip=options.target_ip
    )
    while not folder_queue.empty():
        try:
            folder = folder_queue.get_nowait()
        except queue.Empty:
            break
        logger.info(f"Processing folder: {folder}")
        folders, files = smbClient.list_folder(folder)
        denied_dataLibs = read_denied_dataLibFiles(smbClient)
        for file in files:
            if not file.endswith(".INI"):
                continue
            
            # results are writting into report_queue
            check_fileDataLibRef(file, denied_dataLibs, report_queue, smbClient, config)

        progress_queue.put(folder)
        
        folder_queue.task_done()
        logger.info(f"Processed folder: {folder}")
    smbClient.close()

def report_progress(progress_queue, total_folders):
    """
    Report progress of folder processing using tqdm.
    Args:
        progress_queue (queue.Queue): Queue to report progress.
        total_folders (int): Total number of folders to process.
    """
    with tqdm(total=total_folders, desc="Processing FileLib ...") as pbar:
        handler.setStream(tqdmWriteProxy.get())
        processed_folders = 0
        while processed_folders < total_folders:
            progress_queue.get()
            processed_folders += 1
            pbar.update(1)
            progress_queue.task_done()
    handler.setStream(sys.stdout)

def read_denied_dataLibFiles(smbClient):
    """
    Reads the denied dataLibs from a file on the SMB server.
    Args:
        smbClient (SMBHandler): SMB client instance.
    Returns:
        list: List of denied dataLib names.
    """
    denied_dataLibs = []
    try:
        with open(f"denied_datalibs_{smbClient.address}.txt", "r") as f:
            for line in f:
                denied_dataLibs.append(line.strip())
    except FileNotFoundError:
        logger.error(f"denied_datalibs_{smbClient.address}.txt not found. (must be in pwd)")
        exit(1)
    return denied_dataLibs

def check_fileDataLibRef(filePath, denied_dataLibs, report_queue, smbClient, config):
    """
    Checks a file for denied dataLib references and returns a result if a pattern matches the content
    Args:
        filePath (str): Path to the file to check.
        denied_dataLibs (list): List of denied dataLib names.
        smbClient (SMBHandler): SMB client instance.
        config (dict): Configuration dictionary.
    Returns:
        DataLibResults (list)
    """
    results = []
    try:
        logger.debug(f"Checking file: {filePath}")
        content = smbClient.read_file(filePath).split("\r\n")
        
        for line in content:
            if "=" not in line: # dataLibs are always in the format dataLibName=
                continue
            dataLibName = line.split("=")[0].strip()
            if dataLibName in denied_dataLibs:
                filePath = filePath[:-4]
                filename = filePath.split("\\")[-1]
                print(f"Found denied dataLib reference: {dataLibName} in file: {filePath}")
                #logger.error(f"Found denied dataLib reference: {dataLibName} in file: {filePath}")
                try:
                    inventory_file = f"deniedDatalibs_inventory_{smbClient.address}.csv"
                    with open(inventory_file, "a") as f:
                        f.write(f"{dataLibName};{filePath};\n")
                    return None
                except Exception as ex:
                    logger.error(f"Error writing filename referencing a denied datalibg to file: {inventory_file}", exc_info=True)

                results = check_patterns(
                    filePath,
                    filename,
                    "",
                    "",
                    config,
                    smbClient,
                    ""
                )
                report_queue.put(DataLibResult(dataLibName,f"\\\\{smbClient.address}\\dataLib\\{dataLibName}",results))
        
    except Exception as e:
        logger.error(f"Error reading file {filePath}: {e}")
    return results

def unsecure_datalibs(options, config):
    """
    Main function to search "secure" dataLibs by processing the fileLib directory and checking for denied dataLib references.
    Args:
        options (argparse.Namespace): Command line options.
        config (dict): Configuration dictionary.
    """
    smbClient = SMBHandler()
    smbClient.authenticate_impacket(
        target=options.target,
        dc_ip=options.dc_ip,
        hashes=options.hashes,
        target_ip=options.target_ip
    )
    fileLibPath = f"\\\\{smbClient.target_ip}\\SCCMContentLib$\\fileLib"
    print(f"Listing {fileLibPath}")
    folderList, fileList = smbClient.list_folder(fileLibPath)

    folder_queue = queue.Queue()
    for folder in folderList:
        folder_queue.put(folder)

    progress_queue = queue.Queue()
    report_queue = queue.Queue()
    with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as executor:
        executor.submit(report_progress, progress_queue, folder_queue.qsize()    )
        for _ in range(options.workers):
            executor.submit(
                worker, folder_queue, progress_queue, report_queue, options, config
                )

    findingCount = report_queue.qsize()
    print(f"Everything was scanned. {findingCount} findings found.")
    if findingCount > 0:
        logger.info(f"Generating report...")
        queue_list = []
        while not report_queue.empty():
            queue_list.append(report_queue.get())
        util.report.save_results_to_json(queue_list, f"report_unsecure_datalibs_{smbClient.address}.json")
