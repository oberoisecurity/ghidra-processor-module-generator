//-----------------------------------------------------------------------------
// File: combine.cpp
//
// Combining instructions
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//------------------------------------------------------------------------------
#include <boost/timer/timer.hpp>
#include <boost/thread/thread.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include "combine.h"
#include "bitspan.h"
#include "thread_pool.h"

static bool compareInstructionCombine(const INSTRUCTION_COMBINE& a,
                                      const INSTRUCTION_COMBINE& b);
static bool areInstructionsCombinable(Instruction& a, Instruction& b,
                                      char& replacementChar,
                                      int& differencePosition);
static void combineInstructionsWorker(PARSED_DATA& parsedData,
                                      const string& curBitString,
                                      Instruction* instruction,
                                      set<INSTRUCTION_COMBINE, decltype(compareInstructionCombine)*>& combinedInstructions,
                                      unordered_map<string, unsigned int>& visitedInstructions);

// Set of instructions to combine. It is populated by the workers but only
// inserted into the parserData.combinedInstructions by the parent thread
static set<INSTRUCTION_COMBINE,  decltype(compareInstructionCombine)*> g_TempCombinedInstructions(compareInstructionCombine);

// synchronize access to g_TempCombinedInstructions set
static boost::mutex g_TempCombinedInstructionsMutex;

// Custom comparator for inserting INSTRUCTION_COMBINEs into the 
// g_TempCombinedInstructions set. 
// We want:
// - higher counts (meaning more bits in the bit span)
// - otherwise sort by lower opcode string
static bool compareInstructionCombine(const INSTRUCTION_COMBINE& a,
                                      const INSTRUCTION_COMBINE& b)
{
    if(a.length != b.length)
    {
        // comparison flipped here because we actually want
        // higher counts first in our set
        return a.length > b.length;
    }

    if(a.opcodeA != b.opcodeA)
    {
        return a.opcodeA < b.opcodeA;
    }

    if(a.opcodeB != b.opcodeB)
    {
        return a.opcodeB < b.opcodeB;
    }

    return false;
}

// Returns true if instruction a and b are combinable
static bool areInstructionsCombinable(Instruction& a,
                                      Instruction& b,
                                      char& replacementChar,
                                      int& differencePosition)
{
    bool isEqual = false;

    if(a.getOpcode().length() != b.getOpcode().length())
    {
        // safety check against variable length instructions
        // shouldn't ever hit
        cout << "Attempting to combine different instruction length sizes!!" << endl;
        throw 1;
        return false;
    }

    for(unsigned int j = 0; j < COMBINE_MAX; j++)
    {
        switch(j)
        {
            case COMBINE_DUPLICATES:
                isEqual = a.areInstructionComponentsEqual(&b);
                if(isEqual)
                {
                    replacementChar = '*';
                    return true;
                }
                break;
            case COMBINE_IMMEDIATES:
                isEqual = a.areInstructionComponentsEqualExceptImmediate(&b, &differencePosition);
                if(isEqual == false)
                {
                    isEqual = a.areInstructionComponentsEqualExceptNegativeSign(&b, &differencePosition, TYPE_IMMEDIATE);
                }

                if(isEqual)
                {
                    replacementChar = a.getComponentLetterFromPosition(TYPE_IMMEDIATE, differencePosition);
                    return true;
                }
                break;
            case COMBINE_REGISTERS:
                isEqual = a.areInstructionComponentsEqualExceptRegister(&b, &differencePosition);
                if(isEqual)
                {
                    replacementChar = a.getComponentLetterFromPosition(TYPE_REGISTER, differencePosition);
                    return true;
                }
                break;
            default:
                // BUGBUG: handle errors gracefully
                cout << "[-] Invalid combine type specified!!" << endl;
                return false;
        }
    }

    return false;
}

// Iterates over all bits of the curBitString and attempts to see if
// instruction can be merged with any other instruction one bit away. If a 
// match candidate is found, inserts it into g_TempCombinedInstructions.
// Attempts to find the longest bit span of combinable instructions
static void combineInstructionsWorker(PARSED_DATA& parsedData,
                                      const string& curBitString,
                                      Instruction* instruction,
                                      set<INSTRUCTION_COMBINE, decltype(compareInstructionCombine)*>& combinedInstructions,
                                      unordered_map<string, unsigned int>& visitedInstructions)
{
    BITSPAN longestBitSpan = {0, 0, 0, 0, 0};
    BITSPAN curBitSpan = {0, 0, 0, 0, 0};
    string spanBitString;

    // loop through each bit of the current instruction
    for(unsigned int i = 0; i < curBitString.length(); i++)
    {
        map<string, Instruction*>:: iterator zeroItr;
        map<string, Instruction*>:: iterator oneItr;
        string zeroBitString;
        string oneBitString;
        bool isEqual = false;
        bool hasZero = false;
        char replacementChar = '\0';
        int differencePosition = -1;

        if(curBitString[i] != '0' && curBitString[i] != '1')
        {
            // this bit has already been combined
            // check if it increases our span
            if(curBitString[i] == curBitSpan.replacementChar)
            {
                incrementBitSpan(curBitSpan);
            }
            else
            {
                // we are starting a new bit span
                updateLongestBitSpan(curBitSpan, longestBitSpan);
                initBitSpan(curBitSpan);
                curBitSpan.length = 1;
                curBitSpan.replacementChar = curBitString[i];
            }

            // this is already a combined instruction, no need to do more work
            continue;
        }

        zeroBitString = curBitString;
        oneBitString = curBitString;

        // create two opcoded bit strings:
        // - replace all bits in the span with 0s
        // - replace all bitgs in the span with 1s
        // both new opcode bit strings must be presented and combinable
        // for us to increase our bitspan count
        replacesBitsFromSpan(zeroBitString, i, curBitSpan.length, '0');
        replacesBitsFromSpan(oneBitString, i, curBitSpan.length, '1');

        if(curBitString[i] == '0')
        {
            hasZero = true;
        }

        // current bit position is 0, increment it to a 1 and see if another 
        // string is there
        zeroItr = parsedData.combinedInstructions.find(zeroBitString);
        if(zeroItr == parsedData.combinedInstructions.end())
        {
            // didn't find an adjacent instruction
            if(curBitSpan.length > 0)
            {
                i -= 1;
            }

            updateLongestBitSpan(curBitSpan, longestBitSpan);
            initBitSpan(curBitSpan);
            continue;
        }

        oneItr = parsedData.combinedInstructions.find(oneBitString);
        if(oneItr == parsedData.combinedInstructions.end())
        {
            // didn't find an adjacent instruction
            if(curBitSpan.length > 0)
            {
                i -= 1;
            }

            updateLongestBitSpan(curBitSpan, longestBitSpan);
            initBitSpan(curBitSpan);
            continue;
        }

        //
        // We have a candidate adjacent instruction, check if they are 
        // combinable
        //
        isEqual = areInstructionsCombinable(*zeroItr->second,
                                            *oneItr->second,
                                            replacementChar,
                                            differencePosition);

        // TODO: review this logic
        if(!isEqual)
        {
            // no match
            updateLongestBitSpan(curBitSpan, longestBitSpan);
            initBitSpan(curBitSpan);
            continue;
        }

        // check if instructions are combinable but not the same replacement
        // char
        if(replacementChar != curBitSpan.replacementChar)
        {
            updateLongestBitSpan(curBitSpan, longestBitSpan);
            initBitSpan(curBitSpan);
            incrementBitSpan(curBitSpan);

            if(hasZero)
            {
                curBitSpan.hasZero = true;
                curBitSpan.bitPos = i;
            }
            curBitSpan.replacementChar = replacementChar;
            continue;
        }

        if(isEqual)
        {
            if(hasZero && curBitSpan.hasZero == false)
            {
                curBitSpan.hasZero = true;
                curBitSpan.bitPos = i;
                curBitSpan.replacementChar = replacementChar;
            }

            if(curBitSpan.differencePosition == -1)
            {
                curBitSpan.differencePosition = differencePosition;
            }
        }

        incrementBitSpan(curBitSpan);

    } // for(unsigned int i = 0; i < curBitString.length(); i++)

    updateLongestBitSpan(curBitSpan, longestBitSpan);

    // if longestBitSpan.count is non-zero that means:
    // - we found at least one bit span to combine
    // - this is the longest one
    if(longestBitSpan.length > 0)
    {
        // two instructions to delete
        // new instruction to insert
        unordered_map<string, unsigned int>::iterator itr;
        INSTRUCTION_COMBINE newCombine;
        string tempBitString;

        tempBitString = curBitString;
        tempBitString[longestBitSpan.bitPos] = '1';

        // check if we already have a better match
        itr = visitedInstructions.find(tempBitString);
        if(itr != visitedInstructions.end())
        {
            // we have seen this address already, check if our current span is better or worse
            if(longestBitSpan.length > itr->second)
            {
                // this new span is better, insert it in
                visitedInstructions.insert({{tempBitString, longestBitSpan.length}});
            }
            else
            {
                // this new span is worse, ignore it
                return;
            }
        }
        else
        {
            // we haven't seen this address yet, add it in
            visitedInstructions.insert({{tempBitString, longestBitSpan.length}});
        }

        // instructions are equal, combine them
        newCombine.length = longestBitSpan.length;
        newCombine.instruction = new Instruction();
        *newCombine.instruction = *instruction;

        newCombine.opcodeA = curBitString;
        newCombine.opcodeB = tempBitString;

        tempBitString[longestBitSpan.bitPos] = longestBitSpan.replacementChar;

        //cout << "MATCH " << longestBitSpan.count << " " << longestBitSpan.replacementChar << " " << newCombine.opcodeA << " " << newCombine.opcodeB << " " << tempBitString << endl;

        newCombine.instruction->setOpcodeBitString(tempBitString);
        newCombine.instruction->setCombined(true);
        newCombine.instruction->setNeedsFree(true);

        if(longestBitSpan.differencePosition != -1)
        {
            newCombine.instruction->setComponentPositionCombined(longestBitSpan.differencePosition);
        }

        // insert our newly created instruction into our temp set it will be
        // sorted by bit span count so we can ensure we merge only the optimal
        // instructions into parsedData.combinedInstructions
        combinedInstructions.insert(std::move(newCombine));
    }

    return;
}

static int combineInstructionsThread(PARSED_DATA& parsedData,
                                     unsigned long long start,
                                     unsigned long long end)
{
    map<string, Instruction*>::iterator startItr = parsedData.combinedInstructions.begin();
    map<string, Instruction*>::iterator endItr = parsedData.combinedInstructions.begin();
    set<INSTRUCTION_COMBINE, decltype(compareInstructionCombine)*> combinedInstructions(compareInstructionCombine);
    unordered_map<string, unsigned int> visitedInstructions;

    if(start >= parsedData.combinedInstructions.size() ||
       end >= parsedData.combinedInstructions.size())
    {
        cout << "Bad sizes!!\n";
        cout << start << " " << end << " " << parsedData.combinedInstructions.size() << endl;
        throw 1;
    }

    if(start > end)
    {
        cout << "Bad sizes 2 !!\n";
        cout << start << " " << end << " " << parsedData.combinedInstructions.size() << endl;
        throw 2;
    }

    std::advance(startItr, start);
    endItr = startItr;
    std::advance(endItr, end - start + 1);

    for(; startItr != endItr; startItr++)
    {
        combineInstructionsWorker(parsedData,
                                  startItr->first,
                                  startItr->second,
                                  combinedInstructions,
                                  visitedInstructions);
    }

    g_TempCombinedInstructionsMutex.lock();
    g_TempCombinedInstructions.merge(combinedInstructions);
    g_TempCombinedInstructionsMutex.unlock();

    incrementWorkerCompletions();
    return 0;
}

// Queue each instruction to the thread pool to be combined by worker threads
static unsigned int combineInstructionsScheduler(PARSED_DATA& parsedData)
{
    boost::asio::thread_pool threadPool(parsedData.numThreads);
    unsigned long long numInstructions = 0;
    unsigned long long portionSize = 0;
    unsigned long long start = 0;
    unsigned int submissions = 0;

    resetThreadPool();

    //
    // split the instructions into 1/num threads pieces
    //
    numInstructions = parsedData.combinedInstructions.size();
    portionSize = numInstructions/parsedData.numThreads;

    if(portionSize == 0)
    {
        // we can end up with a 0 portionSize if numThreads > numInstructions
        portionSize = 1;
    }

    for(unsigned int i = 0; i < parsedData.numThreads; i++)
    {
        unsigned long long end = 0;

        start = i * portionSize;

        if(i == parsedData.numThreads - 1)
        {
            // last thread, always set end to numInstructions
            end = numInstructions - 1;
        }
        else
        {
            end = start + portionSize - 1;
        }

        if(start >= numInstructions)
        {
            continue;
        }

        // queue a worker to work on 1/n of the disassembly
        boost::asio::post(threadPool, 
                          boost::bind(combineInstructionsThread,
                                      boost::ref(parsedData),
                                      start,
                                      end));
        submissions++;
    }

    // wait for threads
    // TODO: improve poll logic
    while(1)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        unsigned int completedCount = getWorkerCompletions();

        // check if we finished our submitted jobs
        if(completedCount >= submissions)
        {
            // finished
            break;
        }
    }

    threadPool.join();

    // short-circuit exit if we didn't combine any instructions during this
    // loop
    if(g_TempCombinedInstructions.size() == 0)
    {
        //cout << "  [*] No instructions combined during pass. Short-circuiting" << endl;
        return 0;
    }

    //cout << "g_TempCombinedInstructions: " << g_TempCombinedInstructions.size() << endl;

    g_TempCombinedInstructionsMutex.lock();

    // Update parsedData.combinedInstructions with the newly created combined
    // instructions. Remove two instructions for every onec combined
    // instruction we add back in.
    for(set<INSTRUCTION_COMBINE>:: iterator currItr = g_TempCombinedInstructions.begin();
        currItr != g_TempCombinedInstructions.end();
        currItr++)
    {
        // Verify both opcodeA and opcodeB are present. It's possible we remove
        // one or both while combining another instruction
        auto tempItr = parsedData.combinedInstructions.find(currItr->opcodeA);
        if(tempItr == parsedData.combinedInstructions.end())
        {
            delete currItr->instruction;
            continue;
        }

        auto tempItr2 = parsedData.combinedInstructions.find(currItr->opcodeB);
        if(tempItr2 == parsedData.combinedInstructions.end())
        {
            delete currItr->instruction;
            continue;
        }

        // We only delete instructions that were previously combined as they
        // were allocated here.
        if(tempItr->second->getNeedsFree() == true)
        {
            delete tempItr->second;
        }
        parsedData.combinedInstructions.erase(tempItr);

        if(tempItr2->second->getNeedsFree() == true)
        {
            delete tempItr2->second;
        }
        parsedData.combinedInstructions.erase(tempItr2);

        // insert the new combined instruction
        parsedData.combinedInstructions.insert({{std::move(currItr->instruction->getOpcode()),
                                                           currItr->instruction}});
    }

    g_TempCombinedInstructions.clear();
    g_TempCombinedInstructionsMutex.unlock();

    return 1;
}

// Attempts to combine instructions into one. To combine two instructions into
// one:
// -- the opcodes must bit one bit apart
// -- the instructions must be identical (COMBINE_DUPLICATE)
// -- the instructions must be identical except for an immediate field 
//    (COMBINE_IMMEDIATE)
// -- the instructions must be identical except for a register field
//    (COMBINE_REGISTER)
//
// When we find two instructions to combine we must:
// -- remove the first instruction from combinedInstructions set
// -- remove the second instruction from the combinedInstruction set
// -- change the shared bit to another character such as:
// ---- '*' for duplicates
// ---- lowercase letter for immediates
// ---- uppercase letter for registers
// -- create a new combined instruction and add it to the combinedInstructions
//    set
// -- ensure that we have the best (AKA longest) combination possible
//
// Because we are inserting and deleting while iterating through the set we need be
// careful with our iterators
//
void combineInstructions(PARSED_DATA& parsedData)
{
    boost::timer::auto_cpu_timer t;
    unsigned int result = 0;

    // worst case we must run this algorithm once for every bit in the opcode
    // we have a short-circuit exit if execute a loop without combining any 
    // instructions
    // TODO: is this still true with failures in combining??
    for(unsigned int k = 0; k < parsedData.maxOpcodeBits; k++)
    {
        cout << "  [*] Pass: " << k << " Instructions: " << parsedData.combinedInstructions.size() << endl;

        result = combineInstructionsScheduler(parsedData);
        if(result == 0)
        {
            // no more to combine, return early
            return;
        }
    }

    return;
}
