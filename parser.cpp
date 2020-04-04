//--------------------------------------------------------------------------------------
// File: parser.cpp
//
// Parsing and combining the instructions.
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//--------------------------------------------------------------------------------------

#include "parser.h"
#include "registers.h"

set<string> g_allRegisters;
extern const char* ALL_REGISTERS[];

// Load all the registers extracted from Ghidra into a set
// When parsing the instructions this is how we will tell the difference
// between an instruction mnemonic versus a register
// additionalRegisters is a list of additional registers specified by the user
// at the command line
int initRegisters(vector<string>& additionalRegisters)
{
    set<string>::iterator it;

    for(unsigned int i = 0; i < sizeof(ALL_REGISTERS)/sizeof(ALL_REGISTERS[0]); i++)
    {
        const char* reg = ALL_REGISTERS[i];

        // BUGBUG: bad alloc exception?
        g_allRegisters.insert(reg);
    }

    for(auto additionalRegister : additionalRegisters)
    {
        g_allRegisters.insert(additionalRegister);
    }

    return 0;
}

// returns true if the passed in string is a register
// This is determined seeing if it's in the g_allRegisters set
bool isRegister(string& str)
{
    set<string>::iterator it;

    it = g_allRegisters.find(str);
    if(it == g_allRegisters.end())
    {
        return false;
    }

    return true;
}

// returns true if the passed in string is an opcode
// We determine a string is an opcode if it is a hex string beginning with 0x
bool isOpcode(string& str)
{
    bool result;
    boost::regex expr{"0[xX][0-9a-fA-F]+"};

    result = boost::regex_match(str, expr);

    return result;
}

// returns true if the passed in string is an integer
bool isInteger(string &str)
{
    bool result;
    boost::regex expr{"[0-9]+"};

    result = boost::regex_match(str, expr);

    return result;
}

// an immediate is a hex string or decimal string
bool isImmediate(string& str)
{
	if(isOpcode(str) || isInteger(str))
	{
		return true;
	}

	return false;
}

// tokenizes the input instructions and appends them to the allInstructions set
int parseInstructions(PARSED_DATA& parsedData)
{
    unsigned int lineNum = 0;
    int result = 0;
    std::string line;

    // open the input file for parsing
    boost::filesystem::path infile{parsedData.inputFilename};
    boost::filesystem::ifstream ifs{infile};

    if(!ifs)
    {
        cout << "[-] Failed to open input file!!" << endl;
        return -1;
    }

    //
    // parse the input file line by line
    //
    while (std::getline(ifs, line))
    {
        vector<string> lineSplit;
        ++lineNum;

        Instruction* currInstruction = new Instruction();
        if(currInstruction == NULL)
        {
            cout << "[-] Error line " << lineNum << ": Failed to allocate!!" << endl;
            return -1;
        }

        // We want to split these fillers from register values
        // The simplest way I could come up was to do this but it's slow...
        // BUGBUG: improve performance here
        boost::replace_all(line, ",", " , ");
        boost::replace_all(line, "@", " @ ");
        boost::replace_all(line, "(", " ( ");
        boost::replace_all(line, ")", " ) ");
        boost::replace_all(line, "+", " + ");
        boost::replace_all(line, "-", " - ");
        boost::replace_all(line, "#", " # ");
        boost::trim(line);

        // split the line into components
        boost::split(lineSplit, line, boost::algorithm::is_space(), boost::token_compress_on);

        // our combining algorithm needs to be rewritten to support more than 26 tokens
        // for the time being bail
        if(lineSplit.size() > MAX_TOKENS)
        {
            cout << "[-] Error line " << lineNum << ": Line has more than MAX_TOKENS!!" << endl;
            delete currInstruction;
            return -1;
        }

        // tokenize each line component and add it to the Instruction
        for (unsigned int i = 0; i < lineSplit.size(); i++)
        {
            std::set<string>::iterator it;

            if(i == 0)
            {
                unsigned int opcodeBitLength = 0;

                // the first element on the line must be the opcode
                result = isOpcode(lineSplit[i]);
                if(result != true)
                {
                    cout << "[-] Error line " << lineNum << ": First field is not an hex opcode!!" << endl;
                    cout << "[-] Got: " << lineSplit[i];
                    delete currInstruction;
                    return -1;
                }

                currInstruction->setOpcode(lineSplit[i]);

                // we need to keep track of the maximum bit length for the combining stage
                opcodeBitLength = currInstruction->getOpcode().length();
                if(opcodeBitLength > parsedData.maxOpcodeBits)
                {
                    //cout << "Updating bit length from " << parsedData.maxOpcodeBits << " to " << opcodeBitLength << endl;
                    parsedData.maxOpcodeBits = opcodeBitLength;
                }
            }
            else
            {
                InstructionComponentType currType;

                // all remaining elements on the line are components of the instruction
                if(isRegister(lineSplit[i]))
                {
                    currType = TYPE_REGISTER;
                    parsedData.registers.insert(lineSplit[i]);
                }
                else if(isImmediate(lineSplit[i]))
                {
                    currType = TYPE_IMMEDIATE;
                }
                else
                {
                    currType = TYPE_INSTRUCTION;
                }

                currInstruction->addComponent(currType, lineSplit[i]);
            }
        } // for (int i = 0; i < lineSplit.size(); i++)

        // sanity check the instruction
        result = currInstruction->validateInstruction();
        if(result != true)
        {
            cout << "[-] Error line " << lineNum << ": Instruction is invalid!!" << endl;
            delete currInstruction;
            return -1;
        }

        // check for duplicate instructions before inserting
        if(parsedData.allInstructions.find(currInstruction->getOpcode()) != parsedData.allInstructions.end())
        {
            cout << "[-] Error line " << lineNum << ": Found duplicate opcode!!" << endl;
            delete currInstruction;
            return -1;
        }

        // everything is good, insert instruction into our set
        parsedData.allInstructions.insert({{currInstruction->getOpcode(), currInstruction}});

    } // while (std::getline(ifs, line))

    // copy the instructions into the combined instructions set
    // we need to save the original allInstructions to recreate the registers lists
    // when we print out the instructions
    parsedData.combinedInstructions = parsedData.allInstructions;

    ifs.close();
    return 0;
}

// Attempts to combine instructions into one. To combine two instructions into one:
// -- the opcodes must bit one bit apart
// -- the instructions must be identical (COMBINE_DUPLICATE)
// -- the instructions must be identical except for an immediate field (COMBINE_IMMEDIATE)
// -- the instructions must be identical except for a register field (COMBINE_REGISTER)
//
// When we find two instructions to combine we must:
// -- remove the first instruction from combinedInstructions set
// -- remove the second instruction from the combinedInstruction set
// -- change the shared bit to another character such as:
// ---- '*' for duplicates
// ---- lowercase letter for immediates
// ---- uppercase letter for registers
// -- create a new combined instruction and add it to the combinedInstructions set
//
// Because we are inserting and deleting while iterating through the set we need be careful
// with our iterators
//
void combineInstructions(PARSED_DATA& parsedData, COMBINE_TYPE combineType)
{
    map<string, Instruction*> tempCombinedInstructions; // because we can't insert into a set while iterating over it
                                                        // we temporarily store combined instructions here

    // worst case we must run this algorithm once for every bit in the opcode
    // we have a short-circuit exit if execute a loop without combining any instructions
    for(unsigned int k = 0; k < parsedData.maxOpcodeBits; k++)
    {
        cout << "  [*] Pass: " << k << " Instructions: " << parsedData.combinedInstructions.size() << endl;

        // loop through all of the instructionsone by one
        map<string, Instruction*>:: iterator currItr = parsedData.combinedInstructions.begin();
        while (currItr != parsedData.combinedInstructions.end())
        {
            bool didCombine = false;

            // loop through each bit of the current instruction
            string curBitString = currItr->first;
            for(unsigned int i = 0; i < curBitString.length() && didCombine == false; i++)
            {
                map<string, Instruction*>:: iterator tempItr;
                string tempBitString;
                bool isEqual = false;
                char replacementChar = '*';
                int differencePosition = 0;

                if(curBitString[i] != '0')
                {
                    continue; // we only increment a single bit
                }

                //
                // Check if there is an another instruction where curBitString[i] == '1'
                //

                // current bit position is 0, increment it to a 1 and see if another string is there
                tempBitString = curBitString;
                tempBitString[i] = '1';

                tempItr = parsedData.combinedInstructions.find(tempBitString);
                if(tempItr == parsedData.combinedInstructions.end())
                {
                    // didn't find an adjacent instruction
                    continue;
                }

                //
                // We have a candidate adjacent instruction, check if they are combinable
                //
                switch(combineType)
                {
                    case COMBINE_DUPLICATES:
                        isEqual = currItr->second->areInstructionComonentsEqual(tempItr->second);
                        replacementChar = '*';
                        break;
                    case COMBINE_IMMEDIATES:
                        isEqual = currItr->second->areInstructionComonentsEqualExceptImmediate(tempItr->second, &differencePosition);
                        replacementChar = 'a' + differencePosition - 1;
                        break;
                    case COMBINE_REGISTERS:
                        isEqual = currItr->second->areInstructionComonentsEqualExceptRegister(tempItr->second, &differencePosition);
                        replacementChar = 'A' + differencePosition - 1;
                        break;
                    default:
                        // BUGBUG: handle errors gracefully
                        cout << "[-] Invalid combine type specified!!" << endl;
                        return;
                }

                if(isEqual)
                {
                    // instructions are equal, combine them
                    Instruction* combinedInstruction = currItr->second;

                    // remove the two existing instructions
                    parsedData.combinedInstructions.erase(tempBitString);

                    // this removes the current instruction AND increments our iterator
                    currItr = parsedData.combinedInstructions.erase(currItr);

                    // insert the combined instruction into the tempCombinedInstructions set
                    // it's safe to delete but not insert into a set while iterating through it
                    tempBitString[i] = replacementChar;
                    combinedInstruction->setOpcodeBitString(tempBitString);
                    combinedInstruction->setCombined(true);

                    tempCombinedInstructions.insert({{tempBitString, combinedInstruction}});

                    // we deleted the current instruction, abort the loop
                    didCombine = true;
                    break;
                }
            } // for(int i = 0; i < curBitString.length() && didCombine == false; i++)

            if(didCombine == false)
            {
                // we didn't combine an instruction, increment the iterator manually
                currItr++;
            }
        } //while (currItr != parsedData.combinedInstructions.end())

        // short-circuit exit if we didn't combine any instructions during this loop
        if(tempCombinedInstructions.size() == 0)
        {
            //cout << "  [*] No instructions combined during pass. Short-circuiting" << endl;
            return;
        }

        // we deleted instructions, now merge back in the combined instructions
        for(map<string, Instruction*>:: iterator currItr = tempCombinedInstructions.begin();
            currItr != tempCombinedInstructions.end();
            currItr++)
        {
            parsedData.combinedInstructions.insert({{currItr->first, currItr->second }});
        }
        tempCombinedInstructions.clear();

    } // for(int k = 0; k < parsedData.maxOpcodeBits; k++)

    return;
}

// walks through all instructions that have combined registers and figures out the register list
// and register variable name and appends them to registerVariables. Once registerVariables is filled out
// attachVariables is filled out.
void computeAttachVariables(PARSED_DATA& parsedData)
{
    std::set<Instruction*>::iterator it;

    // iterate through all combined instructions and update registerVariables
    for (auto& x: parsedData.combinedInstructions)
    {
        x.second->computeAttachVariables(parsedData.allInstructions, parsedData.registerVariables);
    }

    for (auto& y: parsedData.registerVariables)
    {
        // y.second = string consisting all delimited by space
        // y.first = register variable name
        parsedData.attachVariables[y.second].insert(y.first);
    }

    return;
}

// walks through all instructions that have combined registers and figures out the register list
// and register variable name and appends them to registerVariables. Once registerVariables is filled out
// attachVariables is filled out.
void computeTokenInstructions(PARSED_DATA& parsedData)
{
    std::set<Instruction*>::iterator it;

    // iterate through all combined instructions. getOpcodeOutputString() will append new tokens
    // to the tokenInstructions set
    for (auto& x: parsedData.combinedInstructions)
    {
        x.second->getOpcodeOutputString(parsedData.tokenInstructions);
    }

    return;
}

// clears the parser data structure
void clearParserData(PARSED_DATA& parsedData)
{
    for (auto& x: parsedData.allInstructions)
    {
        // free the Instructions we allocated
        delete x.second;
    }
    parsedData.allInstructions.clear();

    // no other data structures allocated Instructions
    parsedData.combinedInstructions.clear();
    parsedData.registers.clear();
    parsedData.registerVariables.clear();
    parsedData.attachVariables.clear();
    parsedData.tokenInstructions.clear();
}
