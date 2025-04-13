//-----------------------------------------------------------------------------
// File: bitspan.h
//
// Calculate the longest span of bits that can be combined in an instruction
// opcode
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#pragma once

#include <string>

// represents a span of bits that can be combined
// together in the opcode bitstring
typedef struct _BITSPAN
{
    unsigned int length; // number of bits in bitspan
    char replacementChar;
    unsigned int bitPos;
    int differencePosition;
    bool hasZero;
} BITSPAN, *PBITSPAN;

void initBitSpan(BITSPAN& bitSpan);
void incrementBitSpan(BITSPAN& bitSpan);
void updateLongestBitSpan(BITSPAN& curr, BITSPAN& longest);
void replacesBitsFromSpan(std::string& bitString,
                          unsigned int pos,
                          unsigned int count,
                          char replacementChar);
