//-----------------------------------------------------------------------------
// File: main.cpp
//
// Handles command line argument parsing and calling the parsing, combining, 
// and output routines.
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#include <iostream>
#include <boost/timer/timer.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/thread.hpp>
#include "combine.h"
#include "parser.h"
#include "parser_sla.h"
#include "output.h"
using namespace std;

using namespace boost::filesystem;

int generateFromSleigh(PARSED_DATA& parsedData,
                       bool printRegistersOnly,
                       bool skipInstructionCombining);
int generateFromText(PARSED_DATA& parsedData,
                     bool printRegistersOnly,
                     bool skipInstructionCombining);
int readFilenamesFromDirectory(PARSED_DATA& parsedData,
                               const string& dirPath,
                               const string& extension);

int main(int argc, char *argv[])
{
    boost::program_options::options_description desc{"Ghidra Processor Module Generator"};
    boost::program_options::variables_map args;
    vector<string> additionalRegisters; // list of additional registers passed
                                        // in at the command line
    PARSED_DATA parsedData;
    bool skipInstructionCombining; // if set, skip attempting to combine
                                   // instructions. Useful for debugging
    bool printRegistersOnly; // if set parse the instruction set and only
                             // display the registers. Useful for debugging purposes.
    bool parseSleigh; // if set the input is .sla, not disassembly text
    string inputFilename;
    string inputDirectory;
    boost::timer::auto_cpu_timer t;
    int result = 0;

    parsedData.maxOpcodeBits = 0;
    skipInstructionCombining = false;
    printRegistersOnly = false;
    parseSleigh = false;

    cout << "Ghidra Processor Module Generator" << endl;

    //
    // command line arg parsing
    //

    try
    {
        desc.add_options()
            ("input-disassembly,i", boost::program_options::value<string>(&inputFilename), "Path to a newline delimited text file containing all opcodes and instructions for the processor module.")
            ("input-disassembly-dir", boost::program_options::value<string>(&inputDirectory), "Path to a directory with multiple newline delimited text files containing all opcodes and instructions for the processor module.")
            ("input-sleigh,s", boost::program_options::value<string>(&inputFilename), "Path to a XML .sla file containing all opcodes and instructions for the processor module.")
            ("input-sleigh-dir", boost::program_options::value<string>(&inputDirectory), "Path to a directory with multiple XML .sla files containing all opcodes and instructions for the processor module.")
            ("num-threads,t", boost::program_options::value<unsigned int>(&parsedData.numThreads), "Number of worker threads to use. Optional. Defaults to number of physical CPUs if not specified")
            ("processor-name,n",boost::program_options::value<string>(&parsedData.processorName)->default_value("MyProc"), "Name of the target processor. Defaults to \"MyProc\" if not specified")
            ("processor-family,f",boost::program_options::value<string>(&parsedData.processorFamily)->default_value("MyProcFamily"), "Name of the target processor's family. Defaults to \"MyProcFamily\" if not specified")
            ("endian,e", boost::program_options::value<string>(&parsedData.endianness)->default_value("big"), "Endianness of the processor. Must be either \"little\" or \"big\". Defaults to big if not specified")
            ("alignment,a", boost::program_options::value<unsigned int>(&parsedData.alignment)->default_value(1), "Instruction alignment of the processor. Defaults to 1 if not specified")
            ("bitness,b", boost::program_options::value<unsigned int>(&parsedData.bitness)->default_value(32), "Bitness of the processor. Defaults to 32 if not specified")
            ("print-registers-only", boost::program_options::bool_switch(&printRegistersOnly), "Only print parsed registers. Useful for debugging purposes. False by default")
            ("omit-opcodes", boost::program_options::bool_switch(&parsedData.omitOpcodes)->default_value(false), "Don't print opcodes in the outputted .sla file. False by default")
            ("omit-example-instructions", boost::program_options::bool_switch(&parsedData.omitExampleInstructions)->default_value(false), "Don't print example combined instructions in the outputted .sla file. False by default")
            ("skip-instruction-combining", boost::program_options::bool_switch(&skipInstructionCombining), "Don't combine instructions. Useful for debugging purposes. False by default")
            ("additional-registers,ar", boost::program_options::value<vector<string>>(&additionalRegisters)->multitoken(), "List of additional registers. Use this option if --print-registers-only is missing registers for your instruction set")
            ("help,h", "Help screen");

        store(parse_command_line(argc, argv, desc), args);
        notify(args);

        if(args.count("help") || argc == 1)
        {
            cout << desc << endl;
            return 0;
        }

        if(parsedData.endianness != "big" && parsedData.endianness != "little")
        {
            cout << "Processor endianness must be either little or big" << endl;
            return -1;
        }

        // make sure exactly one input method is specified by the user
        int inputFlagCount = args.count("input-disassembly") +
                             args.count("input-disassembly-dir") + 
                             args.count("input-sleigh") +
                             args.count("input-sleigh-dir");
        if(inputFlagCount != 1)
        {
            cout << "Specifiy exactly one of: --input-disassembly,--input-disassembly-dir, --input-sleigh, or --input-sleigh-dir" << endl;
            return -1;
        }

        if(args.count("input-disassembly") != 0 &&
           args.count("input-disassembly-dir") != 0)
        {
            cout << "Specify either input disassembly file or dir, not both!!" << endl;
            return -1;
        }

        if(args.count("input-disassembly") != 0)
        {
            parsedData.inputFilenames.push_back(inputFilename);
        }

        if(args.count("input-disassembly-dir") != 0)
        {
            result = readFilenamesFromDirectory(parsedData,
                                                inputDirectory,
                                                "*");
            if(result != 0)
            {
                return result;
            }
        }

        if(args.count("input-sleigh") != 0)
        {
            parsedData.inputFilenames.push_back(inputFilename);
            parseSleigh = true;
        }

        if(args.count("input-sleigh-dir") != 0)
        {
            result = readFilenamesFromDirectory(parsedData,
                                                inputDirectory,
                                                ".sla");
            if(result != 0)
            {
                cout << "Failed to find any .sla files" << endl;
                return result;
            }
            parseSleigh = true;
        }

        if(parsedData.inputFilenames.size() == 0)
        {
            cout << "Failed to find input files" << endl;
            return -1;
        }

        if(args.count("num-threads") == 0)
        {
            // user didn't specify number of threads
            // default to number of physical cpus
            parsedData.numThreads = boost::thread::physical_concurrency();
            if(parsedData.numThreads == 0)
            {
                cout << "Unable to determine number of CPUs. Please specify thread count with --num-threads at the command line." << endl;
                return -1;
            }
        }

        if(parsedData.numThreads == 0)
        {
            cout << "Invalid number of threads specified" << endl;
            return -1;    
        }
    }
    catch (const boost::program_options::error &ex)
    {
        cout << "[-] Error parsing command line: " << ex.what() << endl;
        return -1;
    }

    cout << "[*] Using " << parsedData.numThreads << " worker thread(s)" << endl;

    //
    // initialize the default set of registers from Ghidra
    //
    cout << "[*] Initializing default Ghidra registers" << endl;
    result = initRegisters();
    if(result != 0)
    {
        cout << "[-] Failed to initialize default Ghidra registers!!" << endl;
        goto ERROR_CLEANUP;
    }

    result = addRegisters(additionalRegisters);
    if(result != 0)
    {
        cout << "[-] Failed to add additional registers!!" << endl;
        goto ERROR_CLEANUP;
    }

    if(parseSleigh == false)
    {
        // user supplied one or more text files of disassembly
        result = generateFromText(parsedData,
                                  printRegistersOnly,
                                  skipInstructionCombining);
        if(!result)
        {
            return result;
        }
    }
    else
    {
        // user supplied one or more .sla files
        result = generateFromSleigh(parsedData,
                                    printRegistersOnly,
                                    skipInstructionCombining);
        if(!result)
        {
            return result;
        }
    }

ERROR_CLEANUP:
    clearParserData(parsedData, false);
    return result;
}

// search directory for all files of extension type
int readFilenamesFromDirectory(PARSED_DATA& parsedData,
                               const string& dirPath,
                               const string& extension)
{
    if(!is_directory(dirPath))
    {
        cout << "Invalid directory: " << dirPath << endl;
        return -1;
    }

    for(auto& dir_entry : boost::make_iterator_range(directory_iterator(dirPath), {}))
    {
        if(extension == "*" || extension == dir_entry.path().extension())
        {
            parsedData.inputFilenames.push_back(dir_entry.path().string());
        }
    }

    // make sure we have at least one input file
    if(parsedData.inputFilenames.size() == 0)
    {
        cout << "Failed to find any input files in: " << dirPath << endl;
        return -1;
    }

    // TODO: numeric sort vs alpha sort?
    sort(parsedData.inputFilenames.begin(), parsedData.inputFilenames.end());

    return 0;
}

// Generate one or more .sla files from the supplied text disassembly files
int generateFromText(PARSED_DATA& parsedData,
                     bool printRegistersOnly,
                     bool skipInstructionCombining)
{
    int result = 0;

    for(unsigned int i = 0; i < parsedData.inputFilenames.size(); i++)
    {
        //
        // read the input file and parse the instructions into parsedData
        //
        cout << "[*] Parsing instructions " << parsedData.inputFilenames[i] << endl;

        result = parseInstructions(parsedData, i);
        if(result != 0)
        {
            cout << "[-] Failed to parse instructions" << endl;
            goto ERROR_CLEANUP;
        }
        cout << "[*] Parsed " << parsedData.allInstructions.size() << " instructions" << endl;

        // only print registers and exit if option is set
        if(printRegistersOnly)
        {
            goto CONTINUE_LOOP;            
        }

        //
        // combine the instructions and process data for output
        //

        // skip combining if option is set
        if(skipInstructionCombining == false)
        {
            cout << "[*] Combining instructions" << endl;
            combineInstructions(parsedData);
        }

        cout << "[*] Computing attach registers" << endl;
        computeAttachVariables(parsedData);

        cout << "[*] Computing token instructions" << endl;
        computeTokenInstructions(parsedData);

        //
        // Output the completed Ghidra Processor Specification
        //

        cout << "[*] Generating Ghidra processor specification" << endl;
        createProcessorModule(parsedData, i);

CONTINUE_LOOP:        
        clearParserData(parsedData, printRegistersOnly);
        result = 0;
    } // for(unsigned int i = 0; i < parsedData.inputFilenames.size(); i++)

    // only print registers and exit if option is set
    if(printRegistersOnly)
    {
        cout << "[*] Found registers: " << getOutputRegisters(parsedData) << endl;
        cout << "[*] Found mnemonics: " << getOutputMnemonics(parsedData) << endl;
        cout << "If there are any issues edit registers.h before proceeding." << endl;

        result = 0;
        goto ERROR_CLEANUP;
    }

    cout << "[*] Creating .ldefs" << endl;
    result = createLdefs(parsedData);
    if(result != 0)
    {
        return result;
    }        

ERROR_CLEANUP:
    clearParserData(parsedData, false);
    return result;
}

// Generate a .sla files from the one or more supplied .sla files
int generateFromSleigh(PARSED_DATA& parsedData,
                       bool printRegistersOnly,
                       bool skipInstructionCombining)
{
    int result = 0;

    for(unsigned int i = 0; i < parsedData.inputFilenames.size(); i++)
    {
        //
        // read the input file and parse the instructions into parsedData
        //
        cout << "[*] Parsing instructions: " << parsedData.inputFilenames[i] << endl;

        result = parseInstructionsSla(parsedData, i);
        if(result != 0)
        {
            cout << "[-] Failed to parse instructions" << endl;
            goto ERROR_CLEANUP;
        }
        cout << "[*] Parsed " << parsedData.combinedInstructions.size() << " instructions" << endl;

        // only print registers and exit if option is set
        if(printRegistersOnly)
        {
            continue;
        }
    }

    // only print registers and exit if option is set
    if(printRegistersOnly)
    {
        cout << "[*] Found registers: " << getOutputRegisters(parsedData) << endl;
        cout << "If there are any issues edit registers.h before proceeding." << endl;
        result = 0;
        goto ERROR_CLEANUP;
    }

    //
    // combine the instructions and process data for output
    //

    // skip combining if option is set
    if(skipInstructionCombining == false)
    {
        cout << "[*] Combining instructions" << endl;
        combineInstructions(parsedData);
    }

    cout << "[*] Computing attach registers" << endl;
    computeAttachVariables(parsedData);

    cout << "[*] Computing token instructions" << endl;
    computeTokenInstructions(parsedData);

    //
    // Output the completed Ghidra Processor Specification
    //

    cout << "[*] Generating Ghidra processor specification" << endl;
    createProcessorModule(parsedData, 0);

    cout << "[*] Created Processor Module Directory" << endl;

    cout << "  [*] Creating .ldefs" << endl;
    parsedData.inputFilenames.resize(1); // TODO: make this a flag to createLdefs
    result = createLdefs(parsedData);
    if(result != 0)
    {
        return result;
    }

ERROR_CLEANUP:
    clearParserData(parsedData, false);
    return result;
}
