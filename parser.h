//--------------------------------------------------------------------------------------
// File: parser.h
//
// Parsing and combining the instructions. Definition for PARSED_DATA structure. 
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#pragma once
#include <iostream>
#include <set>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/regex.hpp>
#include "instruction.h"
using namespace std;

#define MAX_TOKENS 26 // if there are too many tokens we have to change our bit naming algorithm

enum COMBINE_TYPE
{
    COMBINE_DUPLICATES = 0, // instructions are identical except for a single bit in the opcode
    COMBINE_IMMEDIATES = 1, // instructions are identical except for a single bit in the opcode and a single immediate field
    COMBINE_REGISTERS = 2, // instructions are identical except for a single bit in the opcode and a single register field
    COMBINE_MAX = 3,
};

// data we parsed from the instruction set
// we need this to create our output
typedef struct _PARSED_DATA
{
    // all instructions parsed. Instruction* was allocated by new and must be deleted.
    // string = the instruction opcode as a text string of 0s and 1s
    map<string, Instruction*> allInstructions;

    // combined instructions (e.g. merge duplicates, registers, immediates, etc). Shallow copy from allInstructions to start with
    // and for that reason we should not call delete on instructions.
    // string = the combined instrution opcode as a text string 0s, 1s, *s, capital letters (for registers), and lower case registers (for immediates)
    map<string, Instruction*> combinedInstructions;

    // all registers seen while parsing the instruction set
    set<string> registers;

    // number of bits for the biggest instruction opcode parsed
    unsigned int maxOpcodeBits;

    // registerVariables and attachVariables are used for outputting the "attach variables" field in the output
    // key = register variable name. Ex "regA_04_07"
    // value = string of space delimited registers. Ex: "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15"
    map<string, string> registerVariables;

    // can be thought of as an inverse registerVaribles where we group all register variables that have the same list of registers
    // key = string of space delimted registers. Ex: "r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15"
    // value = set of all register variable names that have the same list of registers. Ex "regA_10_10", "regC_10_10", "regE_10_10"
    map<string, set<string>> attachVariables;

    // used for outputting the "define token instr pieces"
    set<string> tokenInstructions;

    //
    // command line options, we need some of these for our output
    //

    // path to the input assembly file. Not needed again after initial parsing
    string inputFilename;

    // endianess or the instruction set. Can be either "big" or "small". Needed in the output files
    string endian;

    // name of the processor
    string processorName;

    // family of the processor
    string processorFamily;

    // alignment of the instruction set
    unsigned int alignment;

    // whether or not display opcodes as comments in the outputted .sla file
    bool omitOpcodes;

} PARSED_DATA, *PPARSED_DATA;

int initRegisters(void);
bool isImmediate(string& str);
bool isRegister(string& str);
int parseInstructions(PARSED_DATA& parsedData);
void combineInstructions(PARSED_DATA& parsedData, COMBINE_TYPE combineType);
void computeAttachVariables(PARSED_DATA& parsedData);
void computeTokenInstructions(PARSED_DATA& parsedData);
void clearParserData(PARSED_DATA& parsedData);
