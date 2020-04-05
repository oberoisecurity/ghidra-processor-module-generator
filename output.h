//--------------------------------------------------------------------------------------
// File: output.h
//
// Outputs the files that comprise the Ghidra processor module.
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#pragma once
#include "parser.h"
using namespace std;

int createProcessorModule(PARSED_DATA& parsedData);
int createDirectoryStructure(PARSED_DATA& parsedData);
int createModuleManifest(PARSED_DATA& parsedData);
int createPspec(PARSED_DATA& parsedData);
int createCspec(PARSED_DATA& parsedData);
int createLdefs(PARSED_DATA& parsedData);
int createSlaspec(PARSED_DATA& parsedData);

string getOutputRegisters(PARSED_DATA& parsedData);
string getOutputTokenInstructions(PARSED_DATA& parsedData);
string getOutputAttachVariables(PARSED_DATA& parsedData);
string getOutputInstruction(Instruction* instruction, PARSED_DATA& parserData);
string getOriginalOutputString(Instruction* instruction, PARSED_DATA& parsedData);
