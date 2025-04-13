//-----------------------------------------------------------------------------
// File: combine.h
//
// Combining instructions
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#pragma once

#include "parser.h"

// two instructions to combine to a single one
typedef struct _INSTRUCTION_COMBINE
{
    unsigned int length; // count of bits being combined
    Instruction* instruction;
    string opcodeA;
    string opcodeB;
} INSTRUCTION_COMBINE, *PINSTRUCTION_COMBINE;

void combineInstructions(PARSED_DATA& parsedData);
