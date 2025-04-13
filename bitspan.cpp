//-----------------------------------------------------------------------------
// File: bitspan.cpp
//
// Calculate the longest span of bits that can be combined in an instruction
// opcode
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#include "bitspan.h"

// initialize bitspan
void initBitSpan(BITSPAN& bitSpan)
{
    bitSpan.length = 0;
    bitSpan.replacementChar = '\0';
    bitSpan.differencePosition = -1;
    bitSpan.bitPos = 0;
    bitSpan.hasZero = false;
}

// increment the bit span size
void incrementBitSpan(BITSPAN& bitSpan)
{
    bitSpan.length++;
}

// update longest bitspan if curr is longer
// We only want to combine the longest bitspans
void updateLongestBitSpan(BITSPAN& curr, BITSPAN& longest)
{
    if(curr.length <= longest.length)
    {
        return;
    }

    // we only care if the current bitspan has a 0 that we can move to 1
    if(curr.hasZero == false)
    {
        // longer string but no zero
        return;
    }

    if(curr.replacementChar == '\0')
    {
        // should never happen
        return;
    }

    // update longest bitspan
    longest = curr;
    return;
}

// replaces all 0s and 1s in the string with replacementChar starting at 
// position pos
void replacesBitsFromSpan(std::string& bitString,
                          unsigned int pos,
                          unsigned int count,
                          char replacementChar)
{
    bitString[pos] = replacementChar;

    for(unsigned int i = 0; i < count; i++)
    {
        if(bitString[pos - i - 1] == '0' || bitString[pos - i - 1] == '1')
        {
            bitString[pos - i - 1] = replacementChar;
        }
    }
}
