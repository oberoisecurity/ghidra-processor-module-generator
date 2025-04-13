//-----------------------------------------------------------------------------
// File: parser.h
//
// Parsing instructions from disassembly text file
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#pragma once

#include <iostream>
#include <set>
#include <boost/thread/mutex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/regex.hpp>
#include "instruction.h"
#include "slautil/slautil.h"
using namespace std;

// if there are too many tokens we have to change our bit naming algorithm
#define MAX_TOKENS 26 

enum COMBINE_TYPE
{
    COMBINE_DUPLICATES = 0, // instructions are identical except for a single 
                            // bit in the opcode
    COMBINE_IMMEDIATES = 1, // instructions are identical except for a single
                            // bit in the opcode and a single immediate field
    COMBINE_REGISTERS = 2,  // instructions are identical except for a single
                            // bit in the opcode and a single register field
    COMBINE_MAX = 3,
};

// data we parsed from the instruction set
// we need this to create our output
typedef struct _PARSED_DATA
{
    // all instructions parsed. Instruction* was allocated by new and must be 
    // deleted.
    // string = the instruction opcode as a text string of 0s and 1s
    map<string, Instruction*> allInstructions;

    // synchronize access to allinstructions map
    boost::mutex allInstructionsMutex;

    // combined instructions (e.g. merge duplicates, registers, immediates, 
    // etc).
    // Shallow copy from allInstructions to start with and for that reason we
    // should not call delete on instructions.
    // string = the combined instrution opcode as a text string 0s, 1s, *s, 
    // capital letters (for registers), and lower case registers (for 
    // immediates)
    map<string, Instruction*> combinedInstructions;

    // all registers seen while parsing the instruction set
    set<string> registers;

    // synchronize access to registers set
    boost::mutex registersMutex;

    // all instruction mnemonics seen while parsing the instruction set
    // only used for debugging with --print-registers-only option
    set<string> mnemonics;

    // synchronize access to mnemonics set
    boost::mutex mnemonicsMutex;

    // number of bits for the biggest instruction opcode parsed
    unsigned int maxOpcodeBits;

    // synchronize access tot he maxOpcodeBits
    boost::mutex maxOpcodeBitsMutex;

    // set to true if the architecture has variable length instructions
    bool variableLengthISA;

    //
    // Output datas
    //

    // registerVariables and attachVariables are used for outputting the 
    // "attach variables" field in the output
    // key = register variable name. Ex "regA_04_07"
    // value = string of space delimited registers. Ex: "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15"
    map<string, string> registerVariables;

    // can be thought of as an inverse registerVariables where we group all 
    // register variables that have the same list of registers
    // key = string of space delimted registers. Ex: "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15"
    // value = set of all register variable names that have the same list of registers. Ex "regA_10_10", "regC_10_10", "regE_10_10"
    map<string, set<string>> attachVariables;

    // used for outputting the "define token instr pieces"
    // to support variable length architectectures:
    // - [0] - 1 byte instructions
    // - [0] - 2 byte instructions
    // - [0] - 3 byte instructions
    // - [0] - 4 byte instructions
    set<string> tokenInstructions[4];

    // used for outtputing the "duplicated registers" export section
    map<string, unsigned int> duplicatedRegisters;

    //
    // command line options, we need some of these for our output
    //

    // Path to file(s) for parsing
    vector<string> inputFilenames;
    
    // list of loaded .sla files
    // needed similar to the allInstructions map for generating register attach
    // directives
    vector<Slautil> slas;

    // endianess of the instruction set. Can be either "little" or "big".
    // Needed in the output files
    string endianness;

    // name of the processor
    string processorName;

    // family of the processor
    string processorFamily;

    // alignment of the instruction set
    unsigned int alignment;

    // bitness of the instruction set
    unsigned int bitness;

    // whether or not to display opcodes as comments in the outputted .sla file
    // useful for debugging
    bool omitOpcodes;
    
    // whether or not to display an example combined instruction as comments in
    // the outputted .sla file. useful for debugging
    bool omitExampleInstructions;

    // number of threads to use for each thread pool
    // defaults to number of physical CPUs by default
    unsigned int numThreads;

} PARSED_DATA, *PPARSED_DATA;

int initRegisters(void);
int addRegisters(vector<string>& additionalRegisters);
bool isOpcode(const string& str);
bool isInteger(const string &str);
bool isImmediate(const string& str);
bool isRegister(const string& str);
int parseInstructions(PARSED_DATA& parsedData, unsigned int fileId);
void computeAttachVariables(PARSED_DATA& parsedData);
void computeTokenInstructions(PARSED_DATA& parsedData);
void clearParserData(PARSED_DATA& parsedData, bool save_registers);
int convertOpcodeSizeToIndex(unsigned int opcodeSizeInBits);
