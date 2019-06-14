import logging
import os
from os.path import basename
import io
import hashlib

from spdx.checksum import Algorithm
from spdx.creationinfo import Tool
from spdx.document import Document
from spdx.document import License
from spdx.document import ExtractedLicense, ExternalDocumentRef
from spdx.file import File
from spdx.package import Package
from spdx.utils import NoAssert
from spdx.utils import SPDXNone
from spdx.version import Version

TAG_VALUE = "tv"
RDF = "rdf"

def pathOrFileExists(path_or_file):
    return os.path.isdir(path_or_file) or os.path.isfile(path_or_file)

def isPath(path_or_file):
    return os.path.isdir(path_or_file)

def isFile(path_or_file):
    return os.path.isfile(path_or_file)

def get_hash(file_path):
    sha1sum = hashlib.sha1()
    with open(file_path, 'rb') as source:
      block = source.read(2**16)
      while len(block) != 0:
        sha1sum.update(block)
        block = source.read(2**16)
    return sha1sum.hexdigest()

def get_codebase_extra_params(path_or_file):
    return {
    "header": "",
    "tool_name": "SPDXID Doc Generator",
    "tool_version": "1.0",
    "notice": "SPDXID Doc Generator",
    "creator_comment": "Created by SPDXID Document generator",
    "ext_doc_ref": "SPDX-DOC-GENERATOR",
    "doc_ref": "SPDXRef-DOCUMENT",
    "lic_identifier": "CC0-1.0"
    }


def create_spdx_file(path_or_file, output_file_name, id_scan_results, doc_type):
    """
    Write identifier scan results as SPDX Tag/value or RDF.
    """
    code_extra_params = get_codebase_extra_params(path_or_file)
    output_file = None
    if isPath(path_or_file):
        full_file_path = os.path.join(path_or_file, output_file_name + "." + doc_type)
        output_file = open(full_file_path, "wb+")
    else:
        file_dir = os.path.dirname(os.path.abspath(path_or_file))
        full_file_path = os.path.join(file_dir, output_file_name + "." + doc_type)
        output_file = open(full_file_path, "wb+")

    spdx_document = Document(version=Version(2, 1),
                             data_license=License.from_identifier(code_extra_params["lic_identifier"]))
    ext_doc_ref = ExternalDocumentRef(code_extra_params["ext_doc_ref"], code_extra_params["tool_version"], Algorithm("SHA1", get_hash(full_file_path or '')))
    spdx_document.add_ext_document_reference(ext_doc_ref)
    spdx_document.comment = code_extra_params["notice"]
    spdx_document.name = code_extra_params["notice"]
    spdx_document.namespace = code_extra_params["notice"]
    spdx_document.creation_info.add_creator(Tool(code_extra_params["tool_name"] + ' ' + code_extra_params["tool_version"]))
    spdx_document.creation_info.set_created_now()
    spdx_document.creation_info.comment = code_extra_params["creator_comment"]
    spdx_document.spdx_id = code_extra_params["doc_ref"]

    package = spdx_document.package = Package(
        name=basename(path_or_file),
        download_location=NoAssert()
    )

    # Use a set of unique copyrights for the package.
    package.cr_text = set()

    if isPath(path_or_file):
        for file_data in id_scan_results:
            name = file_data["FileName"].replace(path_or_file, '.')
            file_entry = File(
                name=name,
                chk_sum=Algorithm('SHA1', get_hash(file_data["FileName"]) or '')
            )
            spdx_license = License.from_identifier(file_data["SPDXID"])
            file_entry.add_lics(spdx_license)
            package.add_lics_from_file(spdx_license)
            file_entry.conc_lics = NoAssert()
            package.add_file(file_entry)

    if len(package.files) == 0:
        if doc_type == TAG_VALUE:
            output_file.write("# No results for package '{}'.\n".format(package.name))
        else:
            output_file.write("<!-- No results for package '{}'. -->\n".format(package.name))

    if doc_type == TAG_VALUE:
        from spdx.writers.tagvalue import write_document  # NOQA
    else:
        from spdx.writers.rdf import write_document  # NOQA

    if package.files:
        spdx_output = io.StringIO()
        write_document(spdx_document, spdx_output, validate=False)
        result = spdx_output.getvalue()
        if doc_type == TAG_VALUE:
            result = result.encode('utf-8')
        output_file.write(result)
