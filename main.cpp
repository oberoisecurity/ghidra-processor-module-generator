//--------------------------------------------------------------------------------------
// File: main.cpp
//
// Handles command line argument parsing and calling the parsing, combining, and output
// routines.
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include <iostream>
#include <boost/program_options.hpp>
#include "parser.h"
#include "output.h"
using namespace std;

int main(int argc, char *argv[])
{
    boost::program_options::options_description desc{"Ghidra Processor Module Generator"};
    boost::program_options::variables_map args;
    PARSED_DATA parsedData;
    bool skipInstructionCombining; // if set, skip attempting to combine instructions. Useful for debugging purposes.
    bool printRegistersOnly; // if set parse the instruction set and only display the registers. Useful for debugging purposes.
    int result = 0;

    parsedData.maxOpcodeBits = 0;
    skipInstructionCombining = false;
    printRegistersOnly = false;

    cout << "Ghidra Processor Module Generator (GPMG)" << endl;

    //
    // command line arg parsing
    //

    try
    {
        desc.add_options()
            ("input-file,i", boost::program_options::value<string>(&parsedData.inputFilename), "Path to a newline delimited text file containing all opcodes and instructions for the processor module. Required.")
            ("processor-name,n",boost::program_options::value<string>(&parsedData.processorName)->default_value("MyProc"), "Name of the target processor. Defaults to \"MyProc\" if not specified")
            ("processor-family,f",boost::program_options::value<string>(&parsedData.processorFamily)->default_value("MyProcFamily"), "Name of the target processor's family. Defaults to \"MyProcFamily\" if not specified")
            ("endian,e", boost::program_options::value<string>(&parsedData.endian)->default_value("big"), "Endianness of the processor. Must be either \"big\" or \"small\". Defaults to big if not specified")
            ("alignment,a", boost::program_options::value<unsigned int>(&parsedData.alignment)->default_value(1), "Instruction alignment of the processor. Defaults to 1 if not specified")
            ("print-registers-only", boost::program_options::bool_switch(&printRegistersOnly), "Only print parsed registers. Useful for debugging purposes. False by default")
            ("omit-opcodes", boost::program_options::bool_switch(&parsedData.omitOpcodes), "Don't print opcodes in the outputted .sla file. False by default")
            ("skip-instruction-combining", boost::program_options::bool_switch(&skipInstructionCombining), "Don't combine instructions. Useful for debugging purposes. False by default")
            ("help,h", "Help screen");

        store(parse_command_line(argc, argv, desc), args);
        notify(args);

        if(args.count("help") || argc == 1)
        {
            cout << desc << endl;
            return 0;
        }

        if(args.count("input-file") == 0)
        {
            cout << "Input file name is required!!" << endl;
            return -1;
        }

        if(args.count("endiannes") == 0)
        {
            if(parsedData.endian != "big" && parsedData.endian != "small")
            {
                cout << "Processor endianness must be either big or small!!" << endl;
                return -1;
            }
        }
    }
    catch (const boost::program_options::error &ex)
    {
        cout << "[-] Error parsing command line: " << ex.what() << endl;
        return -1;
    }

    //
    // initialize the default set of registers from Ghidra
    //
    cout << "[*] Initializing default Ghidra registers" << endl;

    result = initRegisters();
    if(result != 0)
    {
        cout << "[-] Failed ot initialize default Ghidra registers!!" << endl;
        goto CLEANUP;
    }

    //
    // read the input file and parse the instructions into parsedData
    //
    cout << "[*] Parsing instructions" << endl;

    result = parseInstructions(parsedData);
    if(result != 0)
    {
        cout << "[-] Failed to parse instructions" << endl;
        goto CLEANUP;
    }
    cout << "[*] Parsed " << parsedData.allInstructions.size() << " instructions" << endl;

    // only print registers and exit if option is set
    if(printRegistersOnly)
    {
        cout << "[*] Found registers: " << getOutputRegisters(parsedData) << endl;
        cout << "If there are any issues edit registers.h before proceeding." << endl;
        result = 0;
        goto CLEANUP;
    }

    //
    // combine the instructions and process data for output
    //

    // skip combining if option is set
    if(skipInstructionCombining == false)
    {
        cout << "[*] Combining duplicate instructions" << endl;
        combineInstructions(parsedData, COMBINE_DUPLICATES);

        cout << "[*] Combining immediate instructions" << endl;
        combineInstructions(parsedData, COMBINE_IMMEDIATES);

        cout << "[*] Combining register instructions" << endl;
        combineInstructions(parsedData, COMBINE_REGISTERS);
    }

    cout << "[*] Computing attach registers" << endl;
    computeAttachVariables(parsedData);

    cout << "[*] Computing token instructions" << endl;
    computeTokenInstructions(parsedData);

    //
    // Output the completed Ghidra Processor Specification
    //

    cout << "[*] Generating Ghidra processor specification" << endl;
    createProcessorModule(parsedData);

    cout << "[*] Created Processor Module Directory" << endl;

    result = 0;

    CLEANUP:
        clearParserData(parsedData);
        return result;
}
