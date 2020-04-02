//--------------------------------------------------------------------------------------
// File: output.cpp
//
// Outputs the files that comprise the Ghidra processor module.
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include "output.h"

#include <boost/filesystem.hpp>

// creates the directory structure required by the processor
// processor specs must be in the <ProcessorFamily>/data/languages/ directory structure
int createDirectoryStructure(PARSED_DATA& parsedData)
{
    bool result = false;

    boost::filesystem::path p{parsedData.processorFamily};

    p.append("data");
    p.append("languages");

    if(boost::filesystem::exists(p) && boost::filesystem::is_directory(p))
    {
        // directory already exists
        return 0;
    }

    // create the directory
    // BUGBUG: catch exceptions or use no throw
    result = boost::filesystem::create_directories(p);
    if(result == false)
    {
        cout << "  [-] Failed to create processor directories!!" << endl;
        return -1;
    }

    return 0;
}

// creates an empty Module.manifest inside the <ProcessorFamily> directory
// unsure why this is required by Ghidra
// <ProcessorFamily>/Module.manifest
int createModuleManifest(PARSED_DATA& parsedData)
{
    boost::filesystem::path p{parsedData.processorFamily};

    // BUGBUG: why is this file needed?
    p.append("Module.manifest");

    boost::filesystem::ofstream ofs(p);
    ofs.close();

    return 0;
}

// creates the bare minimum processor cspec file required to be loaded into Ghidra
// It is up to the enduser to fully define this file to get decompiler support to work
// <ProcessorFamily>/data/languages/<Processor>.cspec
int createCspec(PARSED_DATA& parsedData)
{
    string cspecFilename;

    boost::filesystem::path p{parsedData.processorFamily};

    cspecFilename = parsedData.processorFamily + ".cspec";

    p.append("data");
    p.append("languages");
    p.append(cspecFilename);

    boost::filesystem::ofstream ofs(p);

    ofs << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ofs << "\n";
    ofs << "<!-- TODO: setup a valid cspec file -->\n";
    ofs << "<compiler_spec>\n";
    ofs << "\t<default_proto>\n";
    ofs << "\t\t<prototype name=\"__fake\" extrapop=\"0\" stackshift=\"0\">\n";
    ofs << "\t\t\t<input/>\n";
    ofs << "\t\t\t<output/>\n";
    ofs << "\t\t</prototype>\n";
    ofs << "\t</default_proto>\n";
    ofs << "</compiler_spec>\n";

    ofs.close();
    return 0;
}

// creates the bare minimum processor ldefs file required to be loaded into Ghidra
// Uses values passed in at the command line to fill out the file
// <ProcessorFamily>/data/languages/<Processor>.ldefs
int createLdefs(PARSED_DATA& parsedData)
{
    string ldefsFilename;
    string bigOrLittle;

    boost::filesystem::path p{parsedData.processorFamily};

    ldefsFilename = parsedData.processorFamily + ".ldefs";

    p.append("data");
    p.append("languages");
    p.append(ldefsFilename);

    boost::filesystem::ofstream ofs(p);

    if(parsedData.endian == "big")
    {
        bigOrLittle = "BE";
    }
    else
    {
        bigOrLittle = "LE";
    }

    ofs << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ofs << "\n";
    ofs << "<!-- TODO: sanity check these values -->\n";
    ofs << "<language_definitions>\n";
    ofs << "\t<language processor=\"" << parsedData.processorFamily << "\"\n";
    ofs << "\t          endian=\"" << parsedData.endian << "\"\n";
    ofs << "\t          size=\"" << "32" << "\"\n";
    ofs << "\t          variant=\"" << parsedData.processorName << "\"\n";
    ofs << "\t          version=\"1.0\"\n";
    ofs << "\t          slafile=\"" << parsedData.processorName << ".sla\"\n";
    ofs << "\t          processorspec=\"" << parsedData.processorFamily << ".pspec\"\n";
    ofs << "\t          id=\"" << parsedData.processorFamily << ":" << bigOrLittle << ":" << "32" << ":" << parsedData.processorName << "\">\n";
    ofs << "\t\t<description>" << parsedData.processorFamily << " " << parsedData.processorName << " processor 32-bit " << bigOrLittle << "</description>\n";
    ofs << "\t\t<compiler name=\"default\" spec=\"" << parsedData.processorFamily << ".cspec\" id=\"default\"/>\n";
    ofs << "\t</language>\n";
    ofs << "</language_definitions>\n";

    ofs.close();

    return 0;
}

// creates the bare minimum processor pspec file required to be loaded into Ghidra
// It is up to the enduser to fully define this file to get decompiler support to work
// <ProcessorFamily>/data/languages/<Processor>.pspec
int createPspec(PARSED_DATA& parsedData)
{
    string pspecFilename;

    boost::filesystem::path p{parsedData.processorFamily};

    pspecFilename = parsedData.processorFamily + ".pspec";

    p.append("data");
    p.append("languages");
    p.append(pspecFilename);

    boost::filesystem::ofstream ofs(p);

    ofs << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    ofs << "\n";
    ofs << "<processor_spec>\n";
    ofs << "\t<!-- TODO: <programcounter register=\"pc\"/> -->\n";
    ofs << "</processor_spec>\n";

    ofs.close();

    return 0;
}

// Uses the filled out parsedData structure to create a .slaspec file,
// the core of the processor module. This file contains all of the registers,
// defined tokens, and instructions of the instruction set
// <ProcessorFamily>/data/languages/<Processor>.slaspec
int createSlaspec(PARSED_DATA& parsedData)
{
    string pspecFilename;

    boost::filesystem::path p{parsedData.processorFamily};

    pspecFilename = parsedData.processorName + ".slaspec";

    p.append("data");
    p.append("languages");
    p.append(pspecFilename);

    boost::filesystem::ofstream ofs(p);


    ofs << "# File autogenerated by Ghidra Processor Module Generator Generator (GPMG)\n";
    ofs << "# https://github.com/oberoisecurity/ghidra-processor-module-generator\n";
    ofs << "\n";

    // endianness and alignment
    ofs << "# TODO: Verify these\n";
    ofs << "define endian=" << parsedData.endian << ";\n";
    ofs << "define alignment=" << parsedData.alignment << ";\n";
    ofs << "\n";

    // ram and register spaces
    ofs << "# TODO: Verify these\n";
    ofs << "define space ram type=ram_space size=4 wordsize=1 default;\n";
    ofs << "define space register type=register_space size=4;\n";
    ofs << "\n";

    // define registers
    if(parsedData.registers.size() > 0)
    {
        ofs << "# TODO: Verify these\n";
        ofs << "define register offset=0 size=4\n";
        ofs << "[" << getOutputRegisters(parsedData) << "];\n";
        ofs << "\n";
    }

    // flags
    ofs << "# TODO: Add flags if needed\n";
    ofs << "# ex. @define MY_FLAG\t\"my_reg[0,1]\"\n";
    ofs << "\n";

    // define token registers
    if(parsedData.tokenInstructions.size() > 0)
    {
        ofs << "# TODO: Simplify these where possible\n";
        ofs << "# TODO: Combine signed immediates where it makes sense\n";
        ofs << "define token instr(" << parsedData.maxOpcodeBits << ")\n";
        ofs << getOutputTokenInstructions(parsedData);
        ofs << ";\n";
        ofs << "\n";
    }

    // attach variables
    if(parsedData.attachVariables.size() > 0)
    {
        ofs << "# TODO: Simplify these where possible\n";
        ofs << getOutputAttachVariables(parsedData);
        ofs << "\n";
    }

    //
    // Instructions
    //
    ofs << "#\n";
    ofs << "# Instructions\n";
    ofs << "#\n";

    // sorted instructions
    // string = the text of the instruction itself not the opcode
    map<string, Instruction*> sortedCombinedInstructions;

    // sort the instructions
    for(auto combinedInstruction: parsedData.combinedInstructions )
    {
        string instructionString;

        // combinedInstruction.first = the opcode
        // combinedInstruction.second = pointer to the Instruction
        instructionString = getOutputInstruction(combinedInstruction.second, parsedData);
        sortedCombinedInstructions.insert({{instructionString, combinedInstruction.second}});
    }

    for(auto sortedCombinedInstruction: sortedCombinedInstructions)
    {
        string instruction = sortedCombinedInstruction.first;

        // escape forward slash
        boost::replace_all(instruction, "/", "_");

        if(parsedData.omitOpcodes == false)
        {
            ofs << "# " << sortedCombinedInstruction.second->getOpcode() << "\n";
        }
        ofs << instruction << "\n";
        ofs << "{}\n";
        ofs << "\n";
    }
    sortedCombinedInstructions.clear();

    ofs.close();
    return 0;
}

// gets a list of all registers define register section of the processor module
string getOutputRegisters(PARSED_DATA& parsedData)
{
    string output;
    std::set<string>::iterator it;

    for(it = parsedData.registers.begin(); it != parsedData.registers.end(); ++it)
    {
        if(it == parsedData.registers.begin())
        {
            output += *it;
        }
        else
        {
            output += " " + *it;
        }
    }
    return output;
}

// outputs a list of the define token instructions for the processor module
// ex: 
//	imm_00_00 = (0, 0)
//	simm_00_00 = (0, 0) signed
//	imm_00_03 = (0, 3)
//	opcode_00_03 = (0, 3)
//  opcode_00_04 = (0, 4)
//  regA_04_07 = (4, 7)
//	regA_05_05 = (5, 5)
//	regA_05_05_2 = (5, 5)
string getOutputTokenInstructions(PARSED_DATA& parsedData)
{
    string output = "";
    std::set<Instruction*>::iterator it;

    for (auto& token: parsedData.tokenInstructions)
    {
        int start, end;
        vector<string> result;

        boost::split(result, token, boost::is_any_of("_"));
        if(result.size() < 3)
        {
            cout << "Failed to split token!!\n";
            return "";
        }

        start = std::stoi(result[1]);
        end = std::stoi(result[2]);

        output += "\t" + token + " = (" + to_string(start) + ", " + to_string(end) + ")\n";

        // if this was an immediate value, create a signed immediate as well
        // we do this because we can't tell the difference between an unsigned immediate and a postive signed immediate
        if(token.find("imm_") != string::npos)
        {
            output += "\ts" + token + " = (" + to_string(start) + ", " + to_string(end) + ") signed\n";
        }
    }

    return output;
}

// outputs the processor module's attached variables field
// There can be multiple attach variables for a single processor module
// ex: attach variables [ regA_05_05 regC_05_05_2 regE_05_05_2 ] [
//         sr vbr
//     ];
string getOutputAttachVariables(PARSED_DATA& parsedData)
{
    std::set<Instruction*>::iterator it;
    string output = "";

    for (auto& x: parsedData.attachVariables)
    {
        // x.first = string of registers
        // x.second = set containing all register variables using x.first
        string registers;

        for(auto& y: x.second)
        {
            registers += y + " ";
        }

        output += "attach variables [ " + registers + "] [\n";
        output += "\t " + x.first + "\n";
        output += "];\n";
        output += "\n";
    }

    return output;
}

// takes an instruction and converts into SLEIGH format
// example: ":mov rm_04_07, rn_08_11 is opcode_12_15=0b0110 & rn_08_11 & rm_04_07 & opcode_00_03=0b0011"
string getOutputInstruction(Instruction* instruction, PARSED_DATA& parsedData)
{
    string output;

    // instruction decorator
    output += ":";

    output += instruction->getInstructionOutputString();

    output += " is ";

    output += instruction->getOpcodeOutputString(parsedData.tokenInstructions);

    return output;
}

// wrapper function for creating the various files required for the processor module
// parsedData has already been filled out at this point
int createProcessorModule(PARSED_DATA& parsedData)
{
    int result = 0;

    cout << "  [*] Creating Processor Directory Structure" << endl;
    result = createDirectoryStructure(parsedData);
    if(result != 0)
    {
        return result;
    }

    cout << "  [*] Creating Module.manifest" << endl;
    result = createModuleManifest(parsedData);
    if(result != 0)
    {
        return result;
    }

    cout << "  [*] Creating .cspec" << endl;
    result = createCspec(parsedData);
    if(result != 0)
    {
        return result;
    }

    cout << "  [*] Creating .ldefs" << endl;
    result = createLdefs(parsedData);
    if(result != 0)
    {
        return result;
    }

    cout << "  [*] Creating .pspec" << endl;
    result = createPspec(parsedData);
    if(result != 0)
    {
        return result;
    }

    cout << "  [*] Creating .slapec" << endl;
    result = createSlaspec(parsedData);
    if(result != 0)
    {
        return result;
    }

    return 0;
}
