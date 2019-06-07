#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import sys
from .helpers import getAllPaths, getIdentifierForPaths
from .core import pathOrFileExists


def main(project_path):
    pathExists = pathOrFileExists(project_path)
    allPaths = []
    allIdentifiers = []
    if pathExists:
        allPaths = getAllPaths(project_path)
        allIdentifiers = getIdentifierForPaths(allPaths)
    print("Project path", project_path)
    print("path exists", pathExists)
    print("all paths", allPaths)
    print("all identifiers", allIdentifiers)
    sys.exit(0)


def entry_point():
    parser = argparse.ArgumentParser(description='SPDX Document generator help.')
    parser.add_argument('project_path', help='Please add the project path.')
    args = parser.parse_args()
    raise SystemExit(main(args.project_path))


if __name__ == '__main__':
    entry_point()
