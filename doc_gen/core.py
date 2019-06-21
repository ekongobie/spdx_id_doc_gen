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
from .utils import TAG_VALUE, RDF, CODEBASE_EXTRA_PARAMS, FILES_TO_EXCLUDE, pathOrFileExists,
                    isPath, isFile, get_file_hash, get_codebase_extra_params, get_package_file,
                    get_package_version, shouldSkipFile

class SPDXFile(object):
    def __init__(self, path_or_file, output_file_name, id_scan_results, doc_type):
        self.path_or_file = path_or_file
        self.output_file_name = output_file_name
        self.id_scan_results = id_scan_results
        self.doc_type = doc_type
        self.output_file = None
        self.code_extra_params = get_codebase_extra_params(self.path_or_file)
        self.full_file_path = None

    def get_package_version(self):
        return get_package_version(self.path_or_file)

    def get_package_verification_code(self):
        verificationcode = 0
        filelist = ""
        templist = []
        for item in self.id_scan_results:
            if not shouldSkipFile(item["FileName"], self.output_file_name):
                templist.append(get_file_hash(item["FileName"]))
        # sort the sha  values
        templist.sort()
        for item in templist:
            filelist = "{0}{1}".format(filelist, item)
        verificationcode = hashlib.sha1(filelist.encode())
        return verificationcode.hexdigest()

    def get_output_file(self):
        if isPath(self.path_or_file):
            self.full_file_path = os.path.join(self.path_or_file, self.output_file_name + "." + self.doc_type)
            self.output_file = open(self.full_file_path, "wb+")
        else:
            file_dir = os.path.dirname(os.path.abspath(self.path_or_file))
            self.full_file_path = os.path.join(file_dir, self.output_file_name + "." + self.doc_type)
            self.output_file = open(self.full_file_path, "wb+")

    def set_creation_info(self, spdx_document):
        ext_doc_ref = ExternalDocumentRef(self.code_extra_params["ext_doc_ref"], self.code_extra_params["tool_version"], Algorithm("SHA1", get_file_hash(self.full_file_path or '')))
        spdx_document.add_ext_document_reference(ext_doc_ref)
        spdx_document.comment = self.code_extra_params["notice"]
        spdx_document.name = self.code_extra_params["notice"]
        spdx_document.namespace = self.code_extra_params["notice"]
        spdx_document.creation_info.add_creator(Tool(self.code_extra_params["tool_name"] + ' ' + self.code_extra_params["tool_version"]))
        spdx_document.creation_info.set_created_now()
        spdx_document.creation_info.comment = self.code_extra_params["creator_comment"]
        spdx_document.spdx_id = self.code_extra_params["doc_ref"]

    def set_package_info(self, package):
        # Use a set of unique copyrights for the package.
        package.cr_text = set()

        # package.files = ["kfjd"]
        # package.check_sum = "ksdjfnksf ksjdfnskdf"

        package.homepage = "NONE"
        package.verif_code = self.get_package_verification_code()

        package.source_info = "ksdjfnksf ksjdfnskdf"
        # package.conc_lics = "NOASSERTION"
        #
        # package.license_declared = "ksdjfnksf ksjdfnskdf"
        # package.license_comment = "ksdjfnksf ksjdfnskdf"
        #
        # package.licenses_from_files = ["text"]
        # package.summary = "ksdjfnksf ksjdfnskdf"
        #
        # package.description = "ksdjfnksf ksjdfnskdf"
        # package.verif_exc_files = ["kfjd"]

    def create(self):
        """
        Write identifier scan results as SPDX Tag/value or RDF.
        """
        self.get_output_file()
        spdx_document = Document(version=Version(2, 1),
                                 data_license=License.from_identifier(self.code_extra_params["lic_identifier"]))
        self.set_creation_info(spdx_document)
        package = spdx_document.package = Package(
            name=basename(self.path_or_file),
            download_location=NoAssert(),
            version=self.get_package_version()
        )
        self.set_package_info(package)

        if isPath(self.path_or_file):
            for file_data in self.id_scan_results:
                if not shouldSkipFile(file_data["FileName"], self.output_file_name):
                    name = file_data["FileName"].replace(self.path_or_file, '.')
                    file_entry = File(
                        name=name,
                        chk_sum=Algorithm('SHA1', get_file_hash(file_data["FileName"]) or '')
                    )
                    spdx_license = License.from_identifier(file_data["SPDXID"])
                    file_entry.add_lics(spdx_license)
                    package.add_lics_from_file(spdx_license)
                    file_entry.conc_lics = NoAssert()
                    package.add_file(file_entry)

        if len(package.files) == 0:
            if self.doc_type == TAG_VALUE:
                self.output_file.write("# No results for package '{}'.\n".format(package.name))
            else:
                self.output_file.write("<!-- No results for package '{}'. -->\n".format(package.name))

        if self.doc_type == TAG_VALUE:
            from spdx.writers.tagvalue import write_document  # NOQA
        else:
            from spdx.writers.rdf import write_document  # NOQA

        if package.files:
            spdx_output = io.StringIO()
            write_document(spdx_document, spdx_output, validate=False)
            result = spdx_output.getvalue()
            if self.doc_type == TAG_VALUE:
                result = result.encode('utf-8')
            self.output_file.write(result)
