import logging
import os
from .utils import IGNORE_FILENAMES, SKIP_EXTENSIONS, SKIP_DIRECTORIES, HIDE_DIRECTORIES

class ScanData(object):
    def __init__(self):
        self.filename = ""
        self.scanned = False
        self.skipReason = ""
        self.license = None
        self.lineno = -1

    def __str__(self):
        return self.license


def getAllPaths(topDir):
    """Returns a list of all paths for all files within topDir or its children."""
    paths = []
    # ignoring second item in tuple, which lists immediate subdirectories
    for (currentDir, _, filenames) in os.walk(topDir):
        for item in HIDE_DIRECTORIES:
            if item in currentDir:
                continue
            else:
                for filename in filenames:
                    if filename not in IGNORE_FILENAMES:
                        p = os.path.join(currentDir, filename)
                        paths.append(p)
    return paths

def shouldSkipFile(filePath):
    """Returns (True, "reason") if file should be skipped for scanning, (False, "") otherwise."""
    _, extension = os.path.splitext(filePath)
    if extension in SKIP_EXTENSIONS:
        return (True, "skipped file extension")
    for d in SKIP_DIRECTORIES:
        sd = f"/{d}/"
        if sd in filePath:
            return (True, "skipped directory")
    return (False, "")

def parseLineForIdentifier(line):
    """Return parsed SPDX expression if tag found in line, or None otherwise."""
    p = line.partition("SPDX-License-Identifier:")
    if p[2] == "":
        return None
    # strip away trailing comment marks and whitespace, if any
    identifier = p[2].strip()
    identifier = identifier.rstrip("/*")
    identifier = identifier.strip()
    return identifier

def getIdentifierData(filePath, numLines=20):
    """
    Scans the specified file for the first SPDX-License-Identifier:
    tag in the file.

    Arguments:
        - filePath: path to file to scan.
        - numLines: number of lines to scan for an identifier before
                    giving up. If 0, will scan the entire file.
                    Defaults to 20.
    Returns: ScanData with (parsed identifier, line number) if found;
                           (None, -1) if not found.
    """
    # FIXME probably needs to be within a try block
    sd = ScanData()
    sd.filename = filePath
    (shouldSkip, reason) = shouldSkipFile(filePath)
    if shouldSkip:
        logging.debug(f"===> Skipping {filePath}")
        sd.scanned = False
        sd.skipReason = reason
        sd.license = "SKIPPED"
        sd.lineno = -1
        return {
            "FileName": filePath,
            "SPDXID": sd.license,
            "scanned": sd.scanned,
            "FileType": None,
            "FileChecksum": None
        }

    # if we get here, we will scan the file
    sd.scanned = True
    logging.debug(f"Scanning {filePath}")
    with open(filePath, "r") as f:
        try:
            lineno = 0
            for line in f:
                lineno += 1
                if numLines > 0 and lineno > numLines:
                    break
                identifier = parseLineForIdentifier(line)
                if identifier is not None:
                    sd.license = identifier
                    sd.lineno = lineno
                    return {
                        "FileName": filePath,
                        "SPDXID": sd.license,
                        "scanned": sd.scanned,
                        "FileType": None,
                        "FileChecksum": None
                    }
        except UnicodeDecodeError:
            print(f"Encountered invalid UTF-8 content for {filePath}")
            # invalid UTF-8 content
            sd.scanned = False
            sd.skipReason = "encountered invalid UTF-8 content"
            sd.license = "SKIPPED"
            sd.lineno = -1
            return {
                "FileName": filePath,
                "SPDXID": sd.license,
                "scanned": sd.scanned,
                "FileType": None,
                "FileChecksum": None
            }

    # if we get here, we didn't find an identifier
    sd.license = None
    sd.lineno = -1
    return {
        "FileName": filePath,
        "SPDXID": "NOASSERTION",
        "scanned": sd.scanned,
        "FileType": None,
        "FileChecksum": None
    }

def getIdentifierForPaths(paths, numLines=20):
    """
    Scans all specified files for the first SPDX-License-Identifier:
    tag in each file.

    Arguments:
        - paths: list of all file paths to scan.
        - numLines: number of lines to scan for an identifier before
                    giving up. If 0, will scan the entire file.
                    Defaults to 20.
    Returns: dict of {filename: ScanData} for each file in paths.
             ScanData is (parsed identifier, line number) if found;
                         (None, -1) if not found.
    """
    scan_metrics = {
    "with_id": 0,
    "without_id": 0,
    "skipped": 0,
    "total": len(paths)
    }
    results = []
    for filePath in paths:
        id_data = getIdentifierData(filePath, numLines)
        if id_data["SPDXID"] == "SKIPPED":
            scan_metrics["skipped"] = scan_metrics["skipped"] + 1
        if id_data["SPDXID"] == "NOASSERTION":
            scan_metrics["without_id"] = scan_metrics["without_id"] + 1
        if id_data["SPDXID"] != "SKIPPED" and id_data["SPDXID"] != "NOASSERTION":
            scan_metrics["with_id"] = scan_metrics["with_id"] + 1

        results.append(id_data)
    print("Files info: {0}".format(scan_metrics))
    return results


def get_complete_time(function, args=tuple(), kwargs={}):
    """
    ----Decorator----
    Get real, user and system time
    """
    def wrappedMethod(*args, **kwargs):
        from time import time as timestamp
        from resource import getrusage as resource_usage, RUSAGE_SELF
        start_time, start_resources = timestamp(), resource_usage(RUSAGE_SELF)
        func = function(*args, **kwargs)
        end_resources, end_time = resource_usage(RUSAGE_SELF), timestamp()
        results = {'real': end_time - start_time,
                   'sys': end_resources.ru_stime - start_resources.ru_stime,
                   'user': end_resources.ru_utime - start_resources.ru_utime}
        print("Execution time for {0}".format(function.__name__))
        print(results)
        return func
    return wrappedMethod
