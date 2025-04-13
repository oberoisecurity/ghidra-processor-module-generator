//-----------------------------------------------------------------------------
// File: parser_sla.cpp
//
// Parsing and combining the instructions from .sla
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#include "slautil/slautil.h"
#include "parser.h"

// Tokenizes the input instructions from the .sla and appends them to the
// allInstructions set
int parseInstructionsSla(PARSED_DATA& parsedData, unsigned int fileId)
{   
    Slautil slautil;
    vector<string> registers;
    unsigned int count = 0;
    int result = 0;

    result = slautil.loadSla(parsedData.inputFilenames[fileId]);
    if(result != 0)
    {
        return result;
    }

    result = slautil.getConstructorCount(count);
    if(result != 0)
    {
        cout << "Failed to get constructor count" << endl;
        return result;
    }

    result = slautil.getRegisters(registers);
    if(result != 0)
    {
        cout << "Failed to get sla registers" << endl;
        return result;
    }

    result = addRegisters(registers);
    if(result != 0)
    {
        cout << "Failed to add sla registers" << endl;
    }

    for(unsigned int j = 0; j < registers.size(); j++)
    {
        parsedData.registers.insert(registers[j]);
    }

    for(unsigned int i = 0; i < count; i++)
    {
        string bit_pattern;
        string constructor_text;
        string line;
        vector<string> lineSplit;
        Instruction* currInstruction = NULL;
        bool isCombined = false;
        map<string, Instruction*>::iterator itr;

        result = slautil.getConstructorBitPattern(i, bit_pattern);
        if(result != 0)
        {
            cout << "Failed to get bit pattern" << endl;
            return result;
        }

        result = slautil.getConstructorText(i, constructor_text);
        if(result != 0)
        {
            cout << "Failed to get constructor text" << endl;
            return result;
        }
        
        line = bit_pattern + " " + constructor_text;

        // We want to split these fillers from register values
        // The simplest way I could come up was to do this but it's slow...
        // BUGBUG: improve performance here
        // TODO; replace with other impl
        boost::replace_all(line, ",", " , ");
        boost::replace_all(line, "@", " @ ");
        boost::replace_all(line, "(", " ( ");
        boost::replace_all(line, ")", " ) ");
        boost::replace_all(line, "[", " [ ");
        boost::replace_all(line, "]", " ] ");
        boost::replace_all(line, "+", " + ");
        boost::replace_all(line, "-", " - ");
        boost::replace_all(line, "#", " # ");
        boost::replace_all(line, "_DUP", ""); // TODO: hack to workaround not being able to have duplicate
                                              // registers in a single instruction
        boost::trim(line);

        // split the line into components
        boost::split(lineSplit, line, boost::algorithm::is_space(), boost::token_compress_on);

        // Our combining algorithm needs to be rewritten to support more than 
        // 26 tokens. For the time being bail
        if(lineSplit.size() > MAX_TOKENS)
        {
            cout << "[-] Error constructor " << i << ": Line has more than MAX_TOKENS!!" << endl;
            return -1;
        }

        currInstruction = new Instruction();
        if(currInstruction == NULL)
        {
            cout << "[-] Error constructur " << i << ": Failed to allocate!!" << endl;
            return -1;
        }

        // tokenize each line component and add it to the Instruction
        for (unsigned int i = 0; i < lineSplit.size(); i++)
        {
            if(i == 0)
            {
                unsigned int opcodeBitLength = 0;

                currInstruction->setOpcodeBitString(lineSplit[i]);

                // we need to keep track of the maximum bit length for the 
                // combining stage
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

                if (lineSplit[i].find("_DUP") != std::string::npos)
                {
                    std::cout << "found! " << lineSplit[i] << endl;
                    throw 1;
                }            

                // all remaining elements on the line are components of the 
                // instruction
                if(isRegister(lineSplit[i]))
                {
                    currType = TYPE_REGISTER;

                    if(lineSplit[i] == "__register_list__")
                    {
                        currInstruction->setCombined(true);
                        isCombined = true;
                    }
                    else
                    {
                        parsedData.registers.insert(lineSplit[i]);
                    }
                }
                else if(isImmediate(lineSplit[i]))
                {
                    currType = TYPE_IMMEDIATE;

                    if(lineSplit[i] == "__immediate_list__")
                    {
                        currInstruction->setCombined(true);
                        isCombined = true;
                    }
                }
                else
                {
                    currType = TYPE_INSTRUCTION;
                }

                currInstruction->addComponent(currType,
                                              lineSplit[i],
                                              isCombined);
            }
        } // for (int i = 0; i < lineSplit.size(); i++)

        // sanity check the instruction
        result = currInstruction->validateInstruction();
        if(result != true)
        {
            cout << "[-] Error line " << i << ": Instruction is invalid!!" << endl;
            delete currInstruction;
            return -1;
        }

        // check for duplicate instructions before inserting
        itr = parsedData.allInstructions.find(currInstruction->getOpcode());
        if(itr != parsedData.allInstructions.end())
        {
            cout << "[-] Error line " << i << ": Found duplicate opcode!!" << endl;
            delete currInstruction;
            return -1;
        }

        // everything is good, insert instruction into our set
        parsedData.allInstructions.insert({{currInstruction->getOpcode(),
                                            currInstruction}});

    } // for(unsigned int i = 0; i < count; i++)

    // Copy the instructions into the combined instructions set
    // We need to save the original allInstructions to recreate the registers
    // lists when we print out the instructions
    parsedData.combinedInstructions.merge(parsedData.allInstructions);

    parsedData.slas.push_back(slautil);
    return 0;   
}
