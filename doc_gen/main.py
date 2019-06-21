#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import sys
from .helpers import getAllPaths, getIdentifierForPaths
from .core import pathOrFileExists, TAG_VALUE, RDF, SPDXFile


def main(project_path, doc_type):
    pathExists = pathOrFileExists(project_path)
    allPaths = []
    allIdentifiers = []
    spdx_file_name = "spdx_document"
    if pathExists:
        allPaths = getAllPaths(project_path)
        allIdentifiers = getIdentifierForPaths(allPaths)
    if doc_type == TAG_VALUE:
        spdx_file = SPDXFile(project_path, spdx_file_name, allIdentifiers, TAG_VALUE)
        spdx_file.create()
    else:
        spdx_file = SPDXFile(project_path, spdx_file_name, allIdentifiers, RDF)
        spdx_file.create()
    # print("all identifiers in path", allIdentifiers)
    sys.exit(0)


def entry_point():
    parser = argparse.ArgumentParser(description='SPDX Document generator help.')
    parser.add_argument('project_path', help='Please add the project path.')
    parser.add_argument('doc_type', help='Please add the document type.')
    args = parser.parse_args()
    raise SystemExit(main(args.project_path, args.doc_type))


if __name__ == '__main__':
    entry_point()
