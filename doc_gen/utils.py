# SPDX-License-Identifier: Apache-2.0

import logging
import os
from os.path import basename
import io
import hashlib

# filenames to ignore altogether, and not include in reports
IGNORE_FILENAMES = [
    ".DS_Store",
]

# extensions to report on, but skip scanning
SKIP_EXTENSIONS = [
    ".gif",
    ".png",
    ".jpg",
    ".PNG",
    ".pdf",
    ".der",
    ".bin"
]

# directories whose files should be reported on, but skip scanning
SKIP_DIRECTORIES = [
    "LICENSES",
    ".git"
]

# directories whose files should not be reported on and not scanned
HIDE_DIRECTORIES = [
    "spdx_id_doc_gen"
]

# TAG VALUE or RDF
TAG_VALUE = "tv"
RDF = "rdf"

# Codebase extra parameters
CODEBASE_EXTRA_PARAMS = {
                        "header": "",
                        "tool_name": "SPDXID Doc Generator",
                        "tool_name_rdf": "SPDXID.Doc.Generator",
                        "tool_version": "1.0",
                        "notice": "SPDXID Doc Generator",
                        "creator_comment": "Created by SPDXID Document generator",
                        "ext_doc_ref": "SPDX-DOC-GENERATOR",
                        "doc_ref": "SPDXRef-DOCUMENT",
                        "file_ref": "SPDXRef-{0}",
                        "lic_identifier": "CC0-1.0"
                        }

# Files to exclude from scan
FILES_TO_EXCLUDE = ["VERSION", "LICENSE"]

def shouldSkipFile(file_path, output_file):
    should_skip = False
    for item in FILES_TO_EXCLUDE:
        if item in file_path:
            should_skip = True
    if output_file in file_path:
        should_skip = True
    return should_skip

def pathOrFileExists(path_or_file):
    return os.path.isdir(path_or_file) or os.path.isfile(path_or_file)


def isPath(path_or_file):
    return os.path.isdir(path_or_file)


def isFile(path_or_file):
    return os.path.isfile(path_or_file)


def get_file_hash(file_path):
    sha1sum = hashlib.sha1()
    with open(file_path, 'rb') as source:
      block = source.read(2**16)
      while len(block) != 0:
        sha1sum.update(block)
        block = source.read(2**16)
    return sha1sum.hexdigest()


def get_codebase_extra_params(path_or_file):
    return CODEBASE_EXTRA_PARAMS


def get_package_file(path_or_file, file_name):
    if isPath(path_or_file):
        version_file_path = os.path.join(path_or_file, file_name)
        if os.path.exists(version_file_path):
            return version_file_path
    return None

def get_package_version(path_or_file):
    version_file = get_package_file(path_or_file, "VERSION")
    version_major = None
    version_minor = None
    if version_file:
        version_file_content = open(version_file, "r")
        for line in version_file_content:
            if "VERSION_MAJOR" in line:
                version_major = line.split("=")[1]
            if "VERSION_MINOR" in line:
                version_minor = line.split("=")[1]
        if version_major and version_minor:
            return "{0}.{1}".format(version_major.strip(" ").strip("\n"), version_minor.strip(" ").strip("\n"))
    return None
