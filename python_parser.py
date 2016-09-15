#!/usr/bin/env python

import ast
import datetime
import fnmatch
import os
import sys
import time
import unittest
from collections import defaultdict
from fs.zipfs import ZipFS
import bin.ast_utils as ast_utils
from bin.output_generator import Results
from bin.texasranger import Walker
import argparse

"""

"""


class file_extractor(object):
    """
        This class is responsible for unzipping of the zip folder and extracting each source file
        Each file is is then passed to the ast.parse function where the the AST decomposition takes place
        At the end of this class we are passing the list of function and its calls to the result object
        """

    def extract_zip(self, project='.', framework_name=None, output_dir='.'):
        """
        Walk the directory starting at root level, looking for python files.

        Build a "repository" of python classes, functions, etc, and any other
        useful tools. Start the scan from here. Calls to plugins for each type
        of security flaw we're interested in should be dropped in here.

        Keyword arguments:
        root_dir -- root directory to begin crawling (default '.')
        """
        # not sure if this will be useful or not. adding it for posterity
        operating_system = os.name

        source_pyas_dict_dict = {}
        pya_zipfs_dict = {}
        html_files_dict= {}
        css_files_dict={}
        js_files_dict={}
        if not os.path.isdir(project):

            pya_zipfs_dict[project] = extract_to_mem(project)
            source_pyas_dict_dict[project] = find_source_files_zipfs(pya_zipfs_dict[project])


        else:
            archive_files = find_archive_files(project)
            exclusions = []
            for archive_file in archive_files:
                pya_zipfs_dict[archive_file] = extract_to_mem(archive_file)
                source_pyas_dict_dict[archive_file] = find_source_files_zipfs(pya_zipfs_dict[archive_file])


        project_rel_dir = ''
        full_path = ''

        # Scan-related and placeholder tag values for the results XML document.
        predefined_tag_values = {
            './RunInfo/Comment': 'Python Parser',
            './RunInfo/ProjPathname': project,
        }

        results = Results(output_dir, predefined_tag_values)

        # starting scanning the files and store results for later analysis


        results.add_archieve_tag(project)

        my_none_variable = 1

        """
            Here it will walk through all the files in the zip folder
            Next I Parse the source into an AST node adn loop through the walker.function_calls where I get
            the relation between Class, its function and associated calls.
            Appending each element to list and finally passing to the XML tree

            """

        for pya, source_files in source_pyas_dict_dict.items():

            for source_file in source_files:

                rel_path = source_file.strip('/')
                print("Scanning: {0}:".format(source_file))
                openfile = pya_zipfs_dict[pya].open(source_file, 'rb')
                Myfile = rel_path
                mytree = ast.parse(openfile.read())
                walker = Walker(mytree, openfile)
                functioncalls = defaultdict(list)

                class_name_list = []

                func_name_list = []

                func_call_list = []

                """Walking through walker method to get all the Class and its associated calls"""

                for wkrcall in walker.function_calls:

                    functioncalls[ast_utils.find_parents(wkrcall, walker.graph)[0]].append(wkrcall)
                    pFunc, pClass = ast_utils.find_parents(wkrcall, walker.graph)
                    """This checks if pClass,pFunc and Func call is not none"""
                    if pClass is not None:
                        if pFunc is not None:
                            if (ast_utils.construct_full_object_name(wkrcall, walker)[0]) is not None:
                                # print(ast_utils.construct_full_object_name(wkrcall, walker)[0])

                                func_call_list.append(ast_utils.construct_full_object_name(wkrcall, walker)[0])
                                func_name_list.append(pFunc.name)
                                class_name_list.append(pClass.name)

                                """Control comes to this block when pClass is none and checks if pFunc and Func call is not none"""
                    elif ((pFunc is not None) and (
                                    ast_utils.construct_full_object_name(wkrcall, walker)[0] is not None)):
                            #           print(pFunc.name + ' ' + ast_utils.construct_full_object_name(wkrcall, walker)[0])
                            func_call_list.append(ast_utils.construct_full_object_name(wkrcall, walker)[0])
                            func_name_list.append(pFunc.name)
                            class_name_list.append('')

                            """Special case when class and function are null, check if apiCall is null"""
                    else :
                        if(pClass is None) and (pFunc is None) and ((
                                    ast_utils.construct_full_object_name(wkrcall, walker)[0] is not None)):

                           func_call_list.append(ast_utils.construct_full_object_name(wkrcall, walker)[0])
                           func_name_list.append('')
                           class_name_list.append('')



                """Class list,Call list, Function list are sent passed to the Result Object wherein the XML tree format parsing happens"""



                results.add_func_call([source_file, rel_path], class_name_list, func_name_list, func_call_list)
        results.write_output()


##############################   Next Part Deals with All File operations     ######################################################

def find_archive_files(project_dir):
    # Walk over the the directory structure, starting at the root directory,
    # looking for archive files. Compile list.
    archive_files = []
    for dirpath, subdirnames, filenames in os.walk(project_dir):
        for filename in fnmatch.filter(filenames, '*.pya'):
            archive_file = os.path.join(dirpath, filename)
            print ("Adding {0} to list of archives to extract".format(archive_file))
            archive_files.append(archive_file)
    return archive_files


def find_source_files_zipfs(pyazipfs, exclude=[]):
    ''' Walk over the the directory structure, starting at the root directory,
     looking for source files. Creates a list of source files which is stored in source_pyas_dict_dict.'''
    source_files = []
    for source_file in pyazipfs.walkfiles(wildcard='*.py'):
        print ('Adding {0} to list of files to scan'.format(source_file))
        source_files.append(source_file)
    return source_files

def extract_to_mem(archive_file):
    return ZipFS(archive_file)


###################################### End of File Operation Part#############################################

###################################### Main Block ############################################################
if __name__ == "__main__":
    # Run a test

    parser = argparse.ArgumentParser(description='Welcome to Python Interrogator.')
    parser.add_argument('-i', '--input', help='Input file name', required=True)
    parser.add_argument('-o', '--output', help='Output file name', required=True)
    args = parser.parse_args()
    Obj1 = file_extractor()
    framework = None
    Obj1.extract_zip(project=args.input, framework_name=framework, output_dir=args.output)
