# coding: utf-8
# excelcryptohashinglogic.py
# Copyright 2018 iTtelligent, LLC., Kirby J. Davis (kdavis@itelligentllc.com)

"""This file is part of iTelliHashExcel.

    iTelliHashExcel - A Cryptographic Hashing Application for Excel Files
    Copyright (C) 2018 iTtelligent, LLC (Kirby J. Davis)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    """

import gc
import os.path
import re
import sys
from shutil import copyfile

import pandas as pd
import sqlalchemy as sa
import xlwings as xw
from Crypto.Hash import RIPEMD, SHA224, SHA256, SHA384, SHA512
from openpyxl import load_workbook


class StringFolder(object):
    """
    Class that will fold strings. See 'fold_string'.
    This object may be safely deleted or go out of scope when
    strings have been folded.
    """

    def __init__(self):
        self.unicode_map = {}

    def fold_string(self, s):
        """
        Given a string (or unicode) parameter s, return a string object
        that has the same value as s (and may be s). For all objects
        with a given value, the same object will be returned. For unicode
        objects that can be coerced to a string with the same value, a
        string object will be returned.
        If s is not a string or unicode object, it is returned unchanged.
        :param s: a string or unicode object.
        :return: a string or unicode object.
        """
        # If s is not a string or unicode object, return it unchanged
        if not isinstance(s, str):
            return s

        # If s is already a string, then str() has no effect.
        # If s is Unicode, try and encode as a string and use intern.
        # If s is Unicode and can't be encoded as a string, this try
        # will raise a UnicodeEncodeError.
        try:
            return sys.intern(str(s))
        except UnicodeEncodeError:
            # Fall through and handle s as Unicode
            pass

        # Look up the unicode value in the map and return
        # the object from the map. If there is no matching entry,
        # store this unicode object in the map and return it.
        t = self.unicode_map.get(s, None)
        if t is None:
            # Put s in the map
            t = self.unicode_map[s] = s
        return t


def string_folding_wrapper(results):
    """
    This generator yields rows from the results as tuples,
    with all string values folded.
    """
    # Get the list of keys so that we build tuples with all
    # the values in key order.
    keys = list(results.keys())
    folder = StringFolder()
    for row in results:
        yield tuple(
            folder.fold_string(row[key])
            for key in keys
        )


class ExcelCryptoHash(object):
    """
    Logic for hashing selected fields/columns selected by the user from Excel input file selected by the
    user.
    """

    def __init__(self):
        self.hstr = 'sha512'
        self.h = SHA512.new()
        self.files2process = []
        self.fields2encrypt = []
        self.fields2process = []
        self.inputdirectory = ''
        self.outputdirectory = ''

    def initialize_sqlite(self):
        self.SQLiteconnection = sa.create_engine('sqlite:///itellihashexcel.db')

    @staticmethod
    def remove_sqlite():
        os.remove("itellihashexcel.db")
        gc.collect()

    def identify_hash(self, hash2use):
        """ Identify type of cryptographic hashing to use for processing.

        :param hash2use: Value indicating type of hashing desired based upon user's input
        :return: No explicit value returned. Variables set for further processing.

        """
        if hash2use == 1:
            self.h = RIPEMD.new()
            self.hstr = 'ripemd160'
        elif hash2use == 2:
            self.h = SHA224.new()
            self.hstr = 'sha224'
        elif hash2use == 3:
            self.h = SHA256.new()
            self.hstr = 'sha256'
        elif hash2use == 4:
            self.h = SHA384.new()
            self.hstr = 'sha384'
        elif hash2use == 5:
            self.h = SHA512.new()
            self.hstr = 'sha512'

    def hash_text(self, desired_column):
        """ Hash individual fields/columns.

        :param desired_column: Field/column in Excel file to be processed
        :return: self.hashed_value: Hashed value of field/column processed

        """
        h = self.h.new()
        self.hashvalue = h.update(str.encode(str(desired_column)))
        self.hashed_value = h.hexdigest()
        return self.hashed_value

    def create_temp_db(self, fileselected, sheet2process, fields2hash, cols2hash, inputdirectory):
        """ Processing logic for hashing the file and fields/columns selected by the
            user for processing. This function creates an SQLite database that is used during the processing
            to store data, perform in-placed sorting and de-duplication, etc.

        :param inputdirectory: Location of Excel input file(s)
        :param sheet2process: Sheet selected by user to be processed.
        :param fields2hash: List containing the fields/columns selected for processing.
        :param cols2hash: Columns within sheet to be hashed.
        :return: Temporary SQLite database used for subsequent processing.
        """
        fullname = inputdirectory + fileselected

        pdcomposite = pd.read_excel(fullname, sheet2process, index_col=None, parse_cols=cols2hash)

        # Loop through selected fields, hash, and store them
        for field in fields2hash:
            self.compositefile = pdcomposite.loc[:, [field]]
            self.compositefile.drop_duplicates(inplace=True)
            self.compositefile["ColumnName"] = field
            self.compositefile["Plaintext"] = self.compositefile[field]
            self.compositefile["Hashvalue"] = self.compositefile.apply(lambda c: self.hash_text(c.loc[field]), axis=1)
            self.compositefile.drop([field], inplace=True, axis=1)
            self.compositefile.to_sql('data', self.SQLiteconnection, index=False, if_exists="append")

    def process_hash_mapfile_summary(self, fileextension, outputdirectory):
        """ Processing logic for hashing the file and fields/columns selected by the
            user for processing. This function also writes the new 'hashed' version of the input file. An SQLite
            database is used during the processing to store data, perform in-placed sorting and de-duplication, etc.

        :param outputdirectory: Directory chosen for generated output files.
        :param fileextension: File extension of input file.
        :return: Hashed version of Excel input file with the following characteristics:
                 Column Names: Same as original input files. Fields/columns selected for hashing contain the hashed
                               version of the original values.
                 File Name: Hashed_<Original input Excel file name>_<hash format chosen>.<fileextension>
        """

        # Set up ExcelWriter and then write data to summary Excel file
        compositewriter = pd.ExcelWriter(outputdirectory + 'Hash_MapFile_Summary_' + self.hstr + fileextension,
                                         engine='xlsxwriter')

        with self.SQLiteconnection.connect() as connection:
            results = connection.execution_options(stream_results=True).execute(
                'SELECT * FROM data ORDER BY ColumnName, Plaintext')
            df = pd.DataFrame(string_folding_wrapper(results))
            df = df.rename(columns={0: 'ColumnName', 1: 'Plaintext', 2: 'Hashvalue'})
            df.to_excel(compositewriter, 'Hash_MapFile_Summary', index=False)
        compositewriter.save()

    def process_hash_mapfile_detail(self, fields2hash, fileextension, outputdirectory):
        """ Create an output file with a separate mapfile sheet for each field/column selected for hashing with
            column values of Plaintext and Hashvalue.

        :param outputdirectory: Directory chosen for generated output files.
        :param fields2hash: Fields/columns selected to be hashed.
        :param fileextension: File extension of input file.
        :return: Excel detail 'mapfile' for each hashed field/column written to an Excel file with the
                 following characteristics:
                 Column Names: Plaintext,Hashvalue.
                 Sheet Names: Field/column name. One sheet for each field/column chosen for hashing.
                 File Name: Hash_MapFile_Detail_<hash format chosen>.<fileextension>
        """

        self.distinctoutputname = outputdirectory + 'Hash_MapFile_Detail_' + self.hstr + fileextension
        detailwriter = pd.ExcelWriter(self.distinctoutputname)

        for field in fields2hash:
            with self.SQLiteconnection.connect() as connection:
                stmt = sa.text("SELECT * FROM data where ColumnName == :colname ORDER BY Plaintext")
                results = connection.execution_options(stream_results=True).execute(stmt, colname=field)
                df = pd.DataFrame(string_folding_wrapper(results))
                df = df.rename(columns={0: 'ColumnName', 1: 'Plaintext', 2: 'Hashvalue'})
                df.drop('ColumnName', axis=1, inplace=True)
                # Check for invalid Excel sheet name characters and length
                field = re.sub('[\<\>\*\\\/\?|]', '_', field)
                field = re.sub('History', 'Hist', field, flags=re.IGNORECASE)
                field = field[0:30].strip()
                df.to_excel(detailwriter, sheet_name=field, index=False)
        detailwriter.save()

    def create_hashed_outputfile(self, fileselected, sheet2process, fileextension, inputdirectory, outputdirectory):
        """ Create an output file containing the original input file sheet selected for processing with the original
            field/column values plus sheet(s) for each fields/column selected for hashing with column values of
            Plaintext and Hashvalue.

        :param outputdirectory: Directory chosen for generated output files.
        :param inputdirectory: Directory associated with input file.
        :param fileselected: Excel input file selected for processing.
        :param sheet2process: Sheet selected by user to be processed.
        :param fileextension: File extension of input file.
        :return: Hashed Excel output file with the following characteristics:
                 Column Names: Sheet chosen by user for processing: Original input file fields/columns
                               Fields/columns chosen for hashing (on separate sheets): Plaintext,Hashvalue
                 Sheet Names: Original input file sheet selected for processing. Also one sheet for each field/column
                              chosen for hashing.
                 File Name: Hashed_<Input Excel File Name>_<hash format chosen>.<fileextension>

        """
        inputname = inputdirectory + fileselected

        outputname = outputdirectory + 'Hashed_' + fileselected.replace(fileextension, '_' + self.hstr + fileextension)

        xw.App.visible = False

        # Make a copy of the input file as the base for the 'Hashed' output file.
        copyfile(inputname, outputname)

        # Load the output Excel file
        wb = xw.Book(outputname)

        # Load previously created Detail file
        temp_detail = load_workbook(self.distinctoutputname, read_only=True, keep_vba=False)

        for sheet in temp_detail.get_sheet_names():
            xw.sheets.add(sheet, after=sheet2process)
            df = pd.read_excel(self.distinctoutputname, sheet, index_col=None)
            xw.Range('A1').options(index=False).value = df

        wb.save()
        wb.close()
