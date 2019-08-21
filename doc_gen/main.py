#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0

from __future__ import print_function

import os
import argparse
import sys
import glob
from .helpers import getAllPaths, getIdentifierForPaths, get_complete_time
from .core import pathOrFileExists, TAG_VALUE, RDF, SPDXFile
from .utils import isPath, isFile


@get_complete_time
def main_util(item_to_scan, doc_type, skip_pattern, recursive, file_summary_info):
    glob_to_skip = glob.glob(skip_pattern, recursive=recursive) if type(skip_pattern) != list else skip_pattern
    pathExists = pathOrFileExists(item_to_scan)
    is_path = isPath(item_to_scan)
    is_file = isFile(item_to_scan)
    allPaths = []
    allIdentifiers = []
    spdx_file_name = "spdx_document"
    project_path = item_to_scan
    if pathExists:
        if is_file:
            allPaths.append(item_to_scan)
            allIdentifiers = getIdentifierForPaths(allPaths, glob_to_skip)
        if is_path:
            allPaths = getAllPaths(project_path)
            allIdentifiers = getIdentifierForPaths(allPaths, glob_to_skip)
    if doc_type == TAG_VALUE:
        spdx_file = SPDXFile(project_path, spdx_file_name, allIdentifiers, file_summary_info, TAG_VALUE)
        spdx_file.create()
    else:
        spdx_file = SPDXFile(project_path, spdx_file_name, allIdentifiers, file_summary_info, RDF)
        spdx_file.create()

def main(item_to_scan, doc_type, skip_pattern, recursive, file_summary_info):
    main_util(item_to_scan, doc_type, skip_pattern, recursive, file_summary_info)
    sys.exit(0)


def entry_point():
    parser = argparse.ArgumentParser(description='SPDX Document generator help.')
    parser.add_argument('project_path', help='Please add the project path.')
    parser.add_argument('doc_type', help='Please add the document type.')
    parser.add_argument(
    '-skip',
    '--skip',
    dest='skip',
    required=False,
    default=[],
    help='Pattern that will be converted by glob to files that will be skipped.',
)
    parser.add_argument(
    '-rec',
    '--rec',
    dest='recursive',
    action='store_true',
    required=False,
    default=False,
    help='Find files to skip recursively?',
)
    parser.add_argument(
    '-sum',
    '--sum',
    dest='file_summary_info',
    action='store_true',
    required=False,
    default=False,
    help='Add files summary information in spdx file.',
    )
    args = parser.parse_args()
    raise SystemExit(main(args.project_path, args.doc_type, args.skip, args.recursive, args.file_summary_info))


if __name__ == '__main__':
    entry_point()
