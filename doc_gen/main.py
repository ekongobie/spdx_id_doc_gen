#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import argparse
import sys
from .helpers import getAllPaths, getIdentifierForPaths, get_complete_time
from .core import pathOrFileExists, TAG_VALUE, RDF, SPDXFile
from .utils import isPath, isFile


@get_complete_time
def main_util(item_to_scan, doc_type):
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

def main(item_to_scan, doc_type):
    main_util(item_to_scan, doc_type)
    sys.exit(0)


def entry_point():
    parser = argparse.ArgumentParser(description='SPDX Document generator help.')
    parser.add_argument('project_path', help='Please add the project path.')
    parser.add_argument('doc_type', help='Please add the document type.')
    args = parser.parse_args()
    raise SystemExit(main(args.project_path, args.doc_type))


if __name__ == '__main__':
    entry_point()
