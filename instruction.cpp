//-----------------------------------------------------------------------------
// File: instruction.cpp
//
// Instruction class definition
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#include <boost/timer/timer.hpp>
#include "instruction.h"
#include <iostream>
using namespace std;

//
// Misc utility functions
//

// filler instructions should not have spaces after them when outputted
const vector<string> instructionComponentFiller = {"", "@", "(", ")", "[",
                                                   "]", "+", "-", ","};

// returns true if the passed in string is a filler instruction component
bool isInstructionComponentFiller(string& str)
{
    const auto itr = find(instructionComponentFiller.begin(),
                          instructionComponentFiller.end(),
                          str);
    if(itr != instructionComponentFiller.end())
    {
        return true;
    }

    return false;
}

// simple utility to convert an ascii hex char to decimal
int convertHexNibbletoInteger(unsigned char x)
{
    if(x >= '0' && x <= '9')
    {
        return x - '0';
    }

    if(x >= 'A' && x <= 'F')
    {
        return x - 'A' + 0xa;
    }

    if(x >= 'a' && x <= 'f')
    {
        return x - 'a' + 0xa;
    }

    return 0;
}

//
// InstructionComponent
//

InstructionComponent::InstructionComponent(const InstructionComponentType newType,
                                           const string &newComponent)
{
    InstructionComponent(newType, newComponent, false);
}

InstructionComponent::InstructionComponent(const InstructionComponentType newType,
                                           const string &newComponent,
                                           bool isCombined)
{
    this->type = newType;
    this->component = newComponent;
    this->isCombined = isCombined;
}

//
// Instruction
//

// gets the Instruction's opcode string.
// Will be either a strings of 0s and 1s for a regular instruction
// For a combined instruction, will be a string of 0s, 1s, or letters
// representing combined duplicates, immediates, and registers
string Instruction::getOpcode(void)
{
    return this->opcode;
}

// replaces the Instruction's opcode string
void Instruction::setOpcodeBitString(const string &opcodeBitString)
{
    this->opcode = opcodeBitString;
}

// Converts opcodeHexString to a bitString sets it
// opcodeHexString must be a hex string such as 0x112233...
void Instruction::setOpcode(const string &opcodeHexString)
{
    unsigned int high = 0;
    unsigned int low = 0;
    unsigned int value = 0;
    unsigned int numBits = 0;

    if(opcodeHexString.length() < 4 || opcodeHexString.length() % 2 != 0)
    {
        // TODO: should throw here? Instead we will get detected by 
        // validateInstruction()
        cout << "[-] opcodeHexString length is bogus" << endl;
        return;
    }

    // TODO: handle 0b as well
    if(opcodeHexString[0] != '0' ||
      (opcodeHexString[1] != 'x' && opcodeHexString[1] != 'X'))
    {
        cout << "[-] opcodeHexString prefix is bad" << endl;
        return;
    }

    // small perf boost by preallocating the opcode string
    numBits = (opcodeHexString.length() - 2) * 8;
    this->opcode.reserve(numBits);

    // loop through the hex string, converting each byte
    for(unsigned int i = 2; i < opcodeHexString.length(); i += 2)
    {
        // convert the hex string to a byte
        high = convertHexNibbletoInteger(opcodeHexString[i]);
        low = convertHexNibbletoInteger(opcodeHexString[i+1]);

        value = (high << 4) | low;

        // convert the byte to a binary string
        for(int j = 7; j >= 0; j--)
        {
            if(value & (1<<j))
            {
                this->opcode.push_back('1');
            }
            else
            {
                this->opcode.push_back('0');
            }
        } // for(int j = 7; j >= 0; j--)
    } // for(unsigned int i = 2; i < opcodeHexString.length(); i += 2)

    return;
}

// Used for determining whether the instruction was combined or not combined
// instructions have different bitstrings and will need to be outputted
// differently
bool Instruction::getCombined(void)
{
    return this->combined;
}

void Instruction::setCombined(bool isCombined)
{
    this->combined = isCombined;
}

bool Instruction::getNeedsFree(void)
{
    return this->needsFree;
}

void Instruction::setNeedsFree(bool needsFree)
{
    this->needsFree = needsFree;
}

// Adds an instruction component
void Instruction::addComponent(const InstructionComponentType newType,
                               const string &newComponent)
{    
    return addComponent(newType, newComponent, false);
}

void Instruction::addComponent(const InstructionComponentType newType,
                               const string &newComponent,
                               bool isCombined)
{
    if(newType < TYPE_INSTRUCTION || newType >= TYPE_MAX)
    {
        // TODO: should we throw an error instead?
        // I guess this check is unneccessary because we are manually calling
        // this function with validated data
        return;
    }

    this->components.insert(this->components.end(),
                            InstructionComponent(newType, newComponent, isCombined));
}

// Loops through the instruction's components and generates an instruction
// string. Example output: xtrct regA_04_07, regC_08_11
string Instruction::getInstructionOutputString(bool getCombined,
                                               bool escapeDuplicateRegisters)
{
    map<string, unsigned int> registers;
    string output;    
    
    // loop through all the instruction pieces
    for(std::vector<InstructionComponent>::iterator it = this->components.begin();
        it != this->components.end();
        ++it)
    {
        // remove the space if the current component is a comma
        if(it->component == ",")
        {
            boost::trim(output);
        }

        if(getCombined && it->combinedComponent.length() > 0)
        {
            // the instruction has a combined component
            output += it->combinedComponent;

            // hack to support variable length architectures
            if(it->type == TYPE_IMMEDIATE)
            {
                unsigned int opcodeSize = this->getOpcode().length();

                output += "_" + to_string(opcodeSize) + "b";
            }
        }
        else if(it->type == TYPE_INSTRUCTION)
        {
            bool shouldEscape = true;

            // don't escape the first part of the instruction ever
            if(it == this->components.begin())
            {
                shouldEscape = false;
            }
            else if(isInstructionComponentFiller(it->component))
            {
                shouldEscape = false;
            }
            else
            {
                shouldEscape = true;
            }

            if(shouldEscape)
            {
                output += "\"";
            }

            output += it->component;

            if(shouldEscape)
            {
                output += "\"";
            }
        }
        else
        {
            // the instruction does not have a combined component or the caller
            // wants the original instruction
            output += it->component;
            if(escapeDuplicateRegisters && it->type == TYPE_REGISTER)
            {
                map<string, unsigned int>::iterator itr;
                string reg = it->component;

                // do to an issue with Ghidra something like "mov.w @(r0, r0), r0"
                // fails in the SLEIGH compiler due to having multiple repeated
                // registers. The workaround hack is to rename the register and
                // make an export directive
                itr = registers.find(reg);
                if(itr == registers.end())
                {
                    registers[reg] = 1;
                }
                else
                {          
                    string dupVal = "_dup" + std::to_string(registers[reg]);
                    output += dupVal;
                    registers[reg] = registers[reg] + 1;

                }
            }
        }

        if(isInstructionComponentFiller(it->component) || it->type == TYPE_REGISTER)
        {
            output += "";
        }
        else
        {
            output += " ";
        }
    }

    boost::trim(output); // handle the trailing space if there is one
    return output;
}

// Loops through the instruction's components and generates an instruction 
// string. Example output: xtrct regA_04_07, regC_08_11
int Instruction::getInstructionDuplicatedRegisters(bool getCombined,
                                                   map<string, unsigned int>& duplicatedRegisters)
{
    map<string, unsigned int> registers;

    // loop through all the instruction pieces
    for(std::vector<InstructionComponent>::iterator it = this->components.begin();
        it != this->components.end();
        ++it)
    {
        if(getCombined && it->combinedComponent.length() > 0)
        {
            // the instruction has a combined component
            continue;
        }
        else
        {
            if(it->type == TYPE_REGISTER)
            {
                map<string, unsigned int>::iterator itr;
                string reg = it->component;

                // do to an issue with Ghidra something like "mov.w @(r0, r0), r0"
                // fails in the SLEIGH compiler due to having multiple repeated 
                // registers. The workaround hack is to rename the register and
                // make an export directive
                itr = registers.find(reg);
                if(itr == registers.end())
                {
                    registers[reg] = 1;
                }
                else
                {          
                    string dupVal = "_dup" + std::to_string(registers[reg]);
                    registers[reg] = registers[reg] + 1;
                }
            }
        }
    } // for(std::vector<InstructionComponent>::iterator it = this->components.begin(); it != this->components.end(); ++it)

    // update duplicatedRegisters map
    for(auto i = registers.begin();i != registers.end(); i++)
    {
        if(i->second == 1)
        {
            // a register count of 1 is not duplicated
            continue;
        }

        auto j = duplicatedRegisters.find(i->first);
        if(j == duplicatedRegisters.end())
        {
            duplicatedRegisters[i->first] = i->second;
        }
        else if(i->second > j->second)
        {
            duplicatedRegisters[i->first] = i->second;
        }
    }
    return 0;
}

// loops through the instruction's components and generates the opcode string
// example output: opcode_12_15=0b0110 & rn_08_11 & rm_04_07 & opcode_00_03=0b0011
// while looping through all instructions, it appends the tokenInstructions set
// the tokens it comes across
string Instruction::getOpcodeOutputString(set<string>& tokenInstruction)
{
    // so we only print each register once
    map<string, unsigned int> outputtedRegisters;
    bool isFirst = true;
    string output;

    int bitStart = this->opcode.length();

    for(string opcodeString : this->splitOpcode)
    {
        string temp = "";
        string opcodeName = "";
        char opcodeNameBuf[32] = {0};

        if(isFirst != true)
        {
            temp += "& ";
        }

        if(opcodeString[0] == '0' || opcodeString[0] == '1')
        {
            opcodeName = "opcode";
            snprintf(opcodeNameBuf, 
                     sizeof(opcodeNameBuf) - 1,
                     "%s_%02u_%02u_%db",
                     opcodeName.c_str(),
                     (unsigned int)(bitStart - opcodeString.length()),
                     bitStart - 1,
                     (int)this->opcode.length()
                     );
            temp += string(opcodeNameBuf) + "=0b" + opcodeString + " ";
        }
        else if(opcodeString[0] >= 'a' && opcodeString[0] <= 'z')
        {
            opcodeName = "imm";
            snprintf(opcodeNameBuf, 
                     sizeof(opcodeNameBuf) - 1,
                     "%s_%02u_%02u_%db",
                     opcodeName.c_str(),
                     (unsigned int)(bitStart - opcodeString.length()),
                     bitStart - 1,
                     (int)this->opcode.length()
                     );
            temp += string(opcodeNameBuf) + " ";
        }
        else if(opcodeString[0] >= 'A' && opcodeString[0] <= 'Z')
        {
            unsigned int regPos = this->getComponentPositionFromLetter(opcodeString[0]);

            if(this->components[regPos].combinedComponent.length() > 0)
            {
                opcodeName = this->components[regPos].combinedComponent;
            }
            else
            {
                opcodeName = this->components[regPos].component;
            }
            snprintf(opcodeNameBuf,
                     sizeof(opcodeNameBuf) - 1,
                     "%s",
                     opcodeName.c_str()
                     //(int)this->opcode.length()
                     );
            temp += string(opcodeNameBuf) + " ";
        }
        else if(opcodeString[0] == '*')
        {
            // just skip wildcard bits
            bitStart -= opcodeString.length();
            continue;
        }
        else
        {
            // TODO: how to handle error
            cout << "[-] Unknown bit pattern!!" << endl;
            return "";
        }

        output += temp;
        tokenInstruction.insert(opcodeNameBuf);

        bitStart -= opcodeString.length();
        isFirst = false;
    } // for(string opcodeString : this->splitOpcode)

    // if there are registers, add them to the "is" section
    for(std::vector<InstructionComponent>::iterator it = this->components.begin();
        it != this->components.end();
        ++it)
    {
        string reg;

        if(it->type != TYPE_REGISTER)
        {
            continue;
        }

        if(it->combinedComponent.length() > 0)
        {
            reg = it->combinedComponent;
            continue;
        }
        else
        {
            reg = it->component;
        }

        // make sure we haven't already printed this registers
        if(outputtedRegisters.find(reg) != outputtedRegisters.end())
        {
            unsigned int count = outputtedRegisters[reg];
            reg += "_dup" + std::to_string(count);
            outputtedRegisters[reg] = count + 1;
        }
        else
        {
            outputtedRegisters[reg] =  1;
        }

        if(isFirst == false)
        {
            output += "& ";
        }

        output += reg += " ";
        isFirst = false;
    }

    boost::trim_right(output);
    return output;
} // for(std::vector<InstructionComponent>::iterator it = this->components.begin(); it != this->components.end(); ++it)

// helper function to seperate an opcode bitstring into multiple components
// this is a precursor to be able to print the opcode in the .slaspec file
void Instruction::separateOpcode(void)
{
    // opcodes
    string tempOpcodeString;
    tempOpcodeString.push_back(this->opcode[0]);

    this->splitOpcode.clear();

    for(unsigned int i = 1; i < this->opcode.size(); i++)
    {
        int j = tempOpcodeString.size();

        if(tempOpcodeString[j-1] == this->opcode[i])
        {
            // bits are the same, combine them
            tempOpcodeString.push_back(this->opcode[i]);
            continue;
        }
        else if((tempOpcodeString[j-1] == '0' && this->opcode[i] == '1') ||
                (tempOpcodeString[j-1] == '1' && this->opcode[i] == '0'))
        {
            // bits are 0 and 1 we should combine them
            tempOpcodeString.push_back(this->opcode[i]);
            continue;
        }
        else
        {
            // bits are not the same
            this->splitOpcode.push_back(tempOpcodeString);
            tempOpcodeString = "";
            tempOpcodeString.push_back(this->opcode[i]);
            continue;
        }
    }

    // insert the last remaining opcode piece
    this->splitOpcode.push_back(tempOpcodeString);
}

// Basic sanity check of instruction
// TODO: improve this
bool Instruction::validateInstruction(void)
{
    if(this->opcode.size() == 0)
    {
        return false;
    }

    if(this->components.size() == 0)
    {
        return false;
    }

    return true;
}

// Returns true if two instructions are equal
// For an instruction to be equal:
// - there must be the same number of components
// - in the same order
// - of the same type
// - with the same immediate, register, and instruction values
// If this function returns true, the combiner code will replace the
// instruction bit with a '*'
bool Instruction::areInstructionComponentsEqual(Instruction* right)
{
    vector<InstructionComponent> * a;
    vector<InstructionComponent> * b;

    a = &this->components;
    b = &right->components;

    // fast fail if the number of components are different
    if(a->size() != b->size())
    {
        return false;
    }

    // sizes are the same, now loop through each of the components
    for(unsigned int i = 0; i < a->size(); i++)
    {
        // check if the components are of the same type
        if(a->at(i).type != b->at(i).type)
        {
            // an element type is different, fail
            return false;
        }

        // same type, check if the values are the same
        if(a->at(i).component != b->at(i).component)
        {
            return false;
        }
    }

    return true;
}

// Returns true if two instructions are equal except for a single immediate
// field value
// For an instruction to be equal:
// - there must be the same number of components
// - in the same order
// - of the same type
// - with the same immediate, register, and instruction values
// - and a single immediate field must be different
// If this function returns true, the combiner code will replace the 
// instruction bit with a 'a'
// This function has issues with signed immediates. It interprets the "-" as a instruction piece
// and not part of the immediate field. I don't have an easy way to fix this.
bool Instruction::areInstructionComponentsEqualExceptImmediate(Instruction* right,
                                                               int* differencePosition)
{
    vector<InstructionComponent> * a;
    vector<InstructionComponent> * b;

    int numDifferences = 0;

    a = &this->components;
    b = &right->components;

    // fast fail if the number of components are different
    if(a->size() != b->size())
    {
        return false;
    }

    // sizes are the same, now loop through each of the components
    for(unsigned int i = 0; i < a->size(); i++)
    {
        // check if the components are of the same type
        if(a->at(i).type != b->at(i).type)
        {
            // an element type is different, fail
            return false;
        }

        if(a->at(i).type == TYPE_IMMEDIATE)
        {
            if(a->at(i).component == "__immediate_list__" ||
               b->at(i).component == "__immediate_list__" )
            {
                // difference was an register field, make sure this is our only one
                if(numDifferences == 0)
                {
                    numDifferences++;
                    *differencePosition = i;
                    continue;
                }
            }
        }

        // same type, check if the values are the same
        if(a->at(i).component != b->at(i).component)
        {
            // check if the difference was an immediate field
            if(a->at(i).type == TYPE_IMMEDIATE)
            {
                // difference was an register field, make sure this is our only one
                if(numDifferences == 0)
                {
                    numDifferences++;
                    *differencePosition = i;
                    continue;
                }
            }

            return false;
        }
    } // for(unsigned int i = 0; i < a->size(); i++)

    // There must have been atleast one difference
    // we check if it's in the immediate field
    if(numDifferences != 1)
    {
        return false;
    }

    return true;
}

// returns true if two instructions are equal except for a single negative sign
// For an instruction to be equal:
// - one instruction must have an additional negative sign
// - in the same order
// - of the same type
// - with the same immediate, register, and instruction values
// - and a single immediate field must be different
// If this function returns true, the combiner code will replace the instruction
// bit with a 'a'
bool Instruction::areInstructionComponentsEqualExceptNegativeSign(Instruction* right,
                                                                 int* differencePosition,
                                                                 InstructionComponentType componentType)
{
    vector<InstructionComponent> * a;
    vector<InstructionComponent> * b;

    int numDifferences = 0;
    int negativeA = 0;
    int negativeB = 0;

    a = &this->components;
    b = &right->components;

    // fast fail if the number of components are different
    if((a->size() + 1) != b->size() && (a->size() - 1) != b->size())
    {
        return false;
    }

    // sizes are the same, now loop through each of the components
    for(unsigned int i = 0; i < a->size() && i < b->size(); i++)
    {
        // check if the components are of the same type
        if(a->at(i + negativeA).type != b->at(i + negativeB).type)
        {
            // we have the first non-match, check if one is a "-" and the other
            // is an immediate
            if((a->at(i + negativeA).type == componentType) &&
               (b->at(i + negativeB).type == TYPE_INSTRUCTION) &&
               (b->at(i + negativeB).component == "-"))
            {
                    i--;
                    negativeB++;
                    *differencePosition = i;
                    continue;
            }
            else if((b->at(i + negativeB).type == componentType) &&
                    (a->at(i + negativeA).type == TYPE_INSTRUCTION) &&
                    (a->at(i + negativeA).component == "-"))
            {
                    negativeB--;
                    *differencePosition = i;
                    continue;
            }

            // an element type is different, fail
            return false;
        }

        // same type, check if the values are the same
        if(a->at(i + negativeA).component != b->at(i + negativeB).component)
        {
            // check if the difference was an immediate field
            if(a->at(i + negativeA).type == componentType)
            {
                // difference was an register field, make sure this is our only
                // one
                if(numDifferences == 0)
                {
                    numDifferences++;
                    *differencePosition = i;
                    continue;
                }
            }

            return false;
        }
    }

    if((negativeA || negativeB) && numDifferences == 0)
    {
        return true;
    }

    // There must have been atleast one difference
    // we check if it's in the immediate field
    if(numDifferences != 1)
    {
        return false;
    }

    return true;
}

// Returns true if two instructions are equal except for a single register
// field
// For an instruction to be equal:
// - there must be the same number of components
// - in the same order
// - of the same type
// - with the same immediate, register, and instruction values
// - and a single immediate field must be different
// If this function returns true, the combiner code will replace the
// instruction bit with a 'A'
// This function has issues with signed immediates. It interprets the "-" as a
// instruction piece and not part of the immediate field. I don't have an easy
// way to fix this.
bool Instruction::areInstructionComponentsEqualExceptRegister(Instruction* right,
                                                              int* differencePosition)
{
    vector<InstructionComponent> * a;
    vector<InstructionComponent> * b;
    int numDifferences = 0;

    a = &this->components;
    b = &right->components;

    // fast fail if the number of components are different
    if(a->size() != b->size())
    {
        return false;
    }

    // sizes are the same, now loop through each of the components
    for(unsigned int i = 0; i < a->size(); i++)
    {
        // check if the components are of the same type
        if(a->at(i).type != b->at(i).type)
        {
            // an element type is different, fail
            return false;
        }

        // same type, check if the values are the same
        if(a->at(i).component != b->at(i).component)
        {
            // check if the difference was an immediate field
            if(a->at(i).type == TYPE_REGISTER)
            {
                // difference was an register field, make sure this is our only
                // one
                if(numDifferences == 0)
                {
                    numDifferences++;
                    *differencePosition = i;
                    continue;
                }
            }

            return false;
        }
    }

    if(numDifferences == 0)
    {
        cout << "0 differences!!" << endl;
    }

    // There must have been atleast one difference
    // we check if it's in the register field
    if(numDifferences != 1)
    {
        return false;
    }

    return true;
}

int test_getdisassemblysla(string& opcode, vector<Slautil>& slas, unsigned int register_id, string& registerName)
{
    for(unsigned int i = 0; i < slas.size(); i++)
    {        
        int result = 0;
        unsigned int id = 0;

        //cout << "Trying " << i << endl;
        result = slas[i].getConstructorIdByBitPattern(opcode, id);
        if(result != SLA_SUCCESS)
        {
            continue;
        }

        result = slas[i].getConstructorTextRegisterById(id,
                                                        registerName,
                                                        register_id,
                                                        opcode);
        if(result == 0)
        {
            // successfully found the string
            return 0;
        }
    }

    // TODO: 
    cout << "here 1" << endl;
    cout << "completly failed??" << endl;
    return -1;
}

// This function takes an opcode string with variable register bits = 
// ex "0100AAAA"
// and attempts to figure out which registers are used required for the "attach
// variables" directive in the .slaspec. Returns a string of registers in
// foundRegister on success
int Instruction::generateAttachedRegisters(string opcode,
                                           unsigned int regStart,
                                           unsigned int regEnd,
                                           map<string, Instruction*>& allInstructions,
                                           vector<Slautil>& slas, string& foundRegisters)
{
    map<string, Instruction*>::iterator itr;
    int registerPosition = 0;
    int registerLetter = 0;

    registerPosition = this->getComponentPositionFromLetter(opcode[regStart]);
    registerLetter = opcode[regStart];

    // zero out all the non-register regions
    for(unsigned int i = 0; i < opcode.length(); i++)
    {
        // replace all non 0 or 1s with 0
        if(opcode[i] != '0' && opcode[i] != '1')
        {
            opcode[i] = '0';
        }
    }

    // number of iterations for the loop
    unsigned int numIterations = (1 << (regEnd - regStart));

    for(unsigned int i = 0; i < numIterations; i++)
    {
        string tempOpcode = opcode;
        unsigned int bit = i;

        unsigned int pos = 0;
        while(bit)
        {
            if(bit & 1)
            {
                tempOpcode[regEnd - pos - 1] = '1';
            }
            else
            {
                tempOpcode[regEnd - pos - 1] = '0';
            }
            pos++;

            bit = bit/2;
        }

        string reg;

        // TODO: reimplement this with .sla support

        // we created the next opcode, instantiate it and read the register
        // name
        itr = allInstructions.find(tempOpcode);
        if(itr != allInstructions.end())
        {

            reg = itr->second->components[registerPosition].component;
            foundRegisters += reg + " ";
            continue; 
        }

        //cout << "never get here" << endl;
        //throw 2;

        // TODO: cleanup this
        string disassembledString;

        registerPosition = registerLetter - 'A';
        int result = test_getdisassemblysla(tempOpcode,
                                            slas,
                                            registerPosition,
                                            reg);
        if(result == 0)
        {
            foundRegisters += reg + " ";
            continue;
        }

        // TODO: handle this error
        throw 1;

        foundRegisters += "whoops ";
    }

    boost::trim_right(foundRegisters);

    return 0;
}

// Helper function for generating the "attach variable" directive for the 
// .slaspec. This involves figuring out all of the registers needed in a 
// register bitfield
int Instruction::computeAttachVariables(map<string, Instruction*>& allInstructions,
                                        map<string, string>& attachVariables,
                                        vector<Slautil>& slas)
{
    // seperate the opcode into various components
    this->separateOpcode();

    int bitStart = 0;

    // iterate over each component of the opcode looking for register fields
    for(auto& opcodeComponent: this->splitOpcode)
    {
        int position = 0;

        // check if this is a register component
        // only register components have attach variables
        if(opcodeComponent[0] >= 'A' && opcodeComponent[0] <= 'Z')
        {
            string registerName;
            string foundRegisters;

            position = this->getComponentPositionFromLetter(opcodeComponent[0]);

            // generate a list of all attached registers
            int result = generateAttachedRegisters(this->opcode,
                                                   bitStart,
                                                   bitStart + opcodeComponent.length(),
                                                   allInstructions,
                                                   slas,
                                                   foundRegisters);
            if(result != 0)
            {
                cout << "Failed to generate attached registers!!" << endl;
                return -1;
            }

            char regName[16];

            int regEnd = this->opcode.length() - bitStart - 1;
            int regStart = regEnd - opcodeComponent.length() + 1;
            snprintf(regName,
                     sizeof(regName) - 1,
                     "reg%c_%02d_%02d_%db",
                     opcodeComponent[0],
                     regStart,
                     regEnd,
                     (int)this->getOpcode().length()
                     );
            registerName = regName;

            //
            // now that we have the list of registers, we need to name the attach variable itself
            // this is tricky because we can't reuse the same name for different lists of registers
            // To solve that we increment the number of the variable name on collisions
            //

            // TODO: move this to a function
            bool inserted = false;
            int counter = 2;
            while(inserted == false)
            {
                auto itr = attachVariables.find(registerName);
                if(itr == attachVariables.end())
                {
                    attachVariables.insert({{registerName, foundRegisters}});
                    inserted = true;
                }
                else
                {
                    if(foundRegisters == itr->second)
                    {
                        inserted = true;
                    }
                    else
                    {   
                        if(counter > 2 && counter < 10)
                        {
                            // TODO: what if counter is bigger than 10?
                            //cout << "problem here" << endl;
                            registerName.resize(registerName.length() - 2);
                        }
                        else if(counter >= 10 && counter < 100)
                        {
                            registerName.resize(registerName.length() - 3);
                        }
                        else if(counter >= 100)
                        {
                            registerName.resize(registerName.length() - 4);
                        }

                        registerName = registerName + "_" + to_string(counter);
                        //cout << registerName << endl;
                        counter++;
                    }
                }
            }

            this->components[position].combinedComponent = registerName;
        }
        // replace immediate values as well
        else if(opcodeComponent[0] >= 'a' && opcodeComponent[0] <= 'z')
        {
            char immediateName[32];

            int immEnd = this->opcode.length() - bitStart - 1;
            int immStart = immEnd - opcodeComponent.length() + 1;
            snprintf(immediateName, sizeof(immediateName) - 1, "imm_%02d_%02d", immStart, immEnd);

            position = this->getComponentPositionFromLetter(opcodeComponent[0]);
            this->components[position].combinedComponent = string(immediateName);
        }

        bitStart += opcodeComponent.length();
    }

    return 0;
}

int Instruction::setComponentPositionCombined(const unsigned int componentPosition)
{
    if(componentPosition >= this->components.size())
    {
        return -1;
    }

    this->components[componentPosition].isCombined = true;
    return 0;
}

char Instruction::getComponentLetterFromPosition(const InstructionComponentType type,
                                                const unsigned int componentPosition)
{
    int count = 0;

    if(componentPosition >= this->components.size())
    {
        // TODO:
        cout << componentPosition << " " << this->components.size() << endl;
        cout << "here 1111" << endl;
        throw 2;
        return -1;
    }

    for(unsigned int i = 0; 
        i < componentPosition && i < this->components.size();
        i++)
    {
        if(this->components[i].type == type)
        {
            /*
            if(this->components[i].isCombined == false)
            {
                // TODO: we don't assign letters to non-combined registers
                cout << "skipping1: " << this->components[i].component << endl;
                cout << count << " " << endl;
                continue;
            }
            */

            //if(this->components[i].isCombined == true)
            {
                count++;
            }
        }
    }

    if(type == TYPE_REGISTER)
    {
        return 'A' + count;
    }
    else if(type == TYPE_IMMEDIATE)
    {
        return 'a' + count;
    }

    throw 1;
    return -1;
}

unsigned int Instruction::getComponentPositionFromLetter(const char componentLetter)
{
    InstructionComponentType type;
    unsigned int count = 0;

    if(componentLetter >= 'A' && componentLetter <= 'Z')
    {
        type = TYPE_REGISTER;
        count = componentLetter - 'A';
    }
    else if(componentLetter >= 'a' && componentLetter <= 'z')
    {
        type = TYPE_IMMEDIATE;
        count = componentLetter - 'a';
    }
    else
    {
        cout << "Wha the heck" <<  componentLetter << endl;
        cout << "Invalid component letter!!" << endl;
        throw -1;
    }

    for(unsigned int i = 0; i < this->components.size(); i++)
    {
        //cout << i << ") " << this->components[i].component << endl;

        if(this->components[i].type == type)
        {
            /*
            if(this->components[i].isCombined == false)
            {
                // TODO: we don't assign letters to non-combined registers
                cout << "skipping: " << this->components[i].component << endl;
                cout << count << " " << endl;
                continue;
            }
            */

            if(count == 0)
            {
                return i;
            }
            count--;
        }
    }

    cout << "Invalid component count!!" << endl;
    throw -2;
}
