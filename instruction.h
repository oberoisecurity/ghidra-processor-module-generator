//-----------------------------------------------------------------------------
// File: instruction.h
//
// Instruction class definition
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#pragma once

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <set>
#include "slautil/slautil.h"
using namespace std;

enum InstructionComponentType
{
    TYPE_INSTRUCTION = 0,
    TYPE_REGISTER,
    TYPE_IMMEDIATE,
    TYPE_SIGNED_IMMEDIATE, // TODO: not used
    TYPE_MAX, // Not a valid type, must be the last one
};

class InstructionComponent
{
    public:
        InstructionComponent(const InstructionComponentType newType, const string &newComponent);
        InstructionComponent(const InstructionComponentType newType, const string &newComponent, bool isCombined);


        // BUGBUG: should these really be public? I'm treating InstructionComponent more as struct than as a class
        InstructionComponentType type;
        string component;
        string combinedComponent;
        bool isCombined; 
};

class Instruction
{
    public:
        // gets and sets the opcode bitstring
        string getOpcode(void);
        void setOpcode(const string &opcodeBitString); // opcode must be a hex string begining with 0x
        void setOpcodeBitString(const string &newOpcode); // opcode is a binary string without a prefix

        // gets and sets the combined flag
        // BUGBUG: do I really need this??
        bool getCombined(void);
        void setCombined(bool isCombined);
        int setComponentPositionCombined(const unsigned int componentPosition);

        bool getNeedsFree(void);
        void setNeedsFree(bool needsToBeFreed);

        // adds a new instruction component to the instruction
        void addComponent(const InstructionComponentType newType, const string &newComponent);
        void addComponent(const InstructionComponentType newType, const string &newComponent, bool isCombined);

        // helper functions for identifying combined bits by letters
        char getComponentLetterFromPosition(const InstructionComponentType type, const unsigned int componentPosition);
        unsigned int getComponentPositionFromLetter(const char componentLetter);

        // prints the instruction
        string printInstruction(set<string>& tokenInstructions);
        string getInstructionOutputString(bool getCombined, bool escapeDuplicateRegisters);
        int getInstructionDuplicatedRegisters(bool getCombined, map<string, unsigned int>& duplicatedRegisters);
        string getOpcodeOutputString(set<string>& tokenInstructions);

        // basic checks that the instruction is sane
        bool validateInstruction(void);

        // tests to check if two instruction can be combined
        bool areInstructionComponentsEqual(Instruction* right);
        bool areInstructionComponentsEqualExceptImmediate(Instruction* right, int* differencePosition);
        bool areInstructionComponentsEqualExceptNegativeSign(Instruction* right, int* differencePosition, InstructionComponentType componentType);
        bool areInstructionComponentsEqualExceptRegister(Instruction* right, int* differencePosition);

        // for creating the .slaspec
        void separateOpcode();
        int computeAttachVariables(map<string, Instruction*>& allInstructions, map<string, string>& attachVariables, vector<Slautil>& slas);
        int generateAttachedRegisters(string opcode, unsigned int regStart, unsigned int regEnd, map<string, Instruction*>& allInstructions, vector<Slautil>& slas, string& foundRegisters);

    //private:
        string opcode; // entire opcode of instruction in binary
        vector<string> splitOpcode; // opcode split into individual components
        vector<InstructionComponent> components; // the instruction broken up as components
        bool combined; // is the instruction combined or not
        bool needsFree;
};

// misc utility functions used by the Instruction class
// BUGBUG: should this be a part of the class??
int convertHexNibbletoInteger(unsigned char x);
bool isInstructionComponentFiller(string& str);
