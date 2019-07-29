#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import argparse
import sys
import glob
from .helpers import getAllPaths, getIdentifierForPaths, get_complete_time
from .core import pathOrFileExists, TAG_VALUE, RDF, SPDXFile
from .utils import isPath, isFile


@get_complete_time
def main_util(item_to_scan, doc_type, skip_pattern, recursive):
    files_to_skip = glob.glob(skip_pattern, recursive=recursive)
    print(files_to_skip)
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
            allIdentifiers = getIdentifierForPaths(allPaths)
        if is_path:
            allPaths = getAllPaths(project_path)
            allIdentifiers = getIdentifierForPaths(allPaths)
    if doc_type == TAG_VALUE:
        spdx_file = SPDXFile(project_path, spdx_file_name, allIdentifiers, TAG_VALUE)
        spdx_file.create()
    else:
        spdx_file = SPDXFile(project_path, spdx_file_name, allIdentifiers, RDF)
        spdx_file.create()

def main(item_to_scan, doc_type, skip_pattern, recursive):
    main_util(item_to_scan, doc_type, skip_pattern, recursive)
    sys.exit(0)


def entry_point():
    parser = argparse.ArgumentParser(description='SPDX Document generator help.')
    parser.add_argument('project_path', help='Please add the project path.')
    parser.add_argument('doc_type', help='Please add the document type.')
    parser.add_argument('skip', help='Pattern that will be converted by glob to files that will be skipped.')
    parser.add_argument(
    '-rec',
    '--rec',
    dest='recursive',
    action='store_true',
    required=False,
    default=False,
    help='Find files to skip recursively?',
)
    args = parser.parse_args()
    print(args)
    raise SystemExit(main(args.project_path, args.doc_type, args.skip, args.recursive))


if __name__ == '__main__':
    entry_point()
