import logging
import os

def pathOrFileExists(path_or_file):
    return os.path.isdir(path_or_file) or os.path.isfile(path_or_file)
