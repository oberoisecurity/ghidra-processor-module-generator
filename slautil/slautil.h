//-----------------------------------------------------------------------------
// File: slautil.h
//
// Misc helper functions for working with .sla files
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/unordered_map.hpp>
#include <string>
#include <iostream>
#include <fstream>

using namespace std;
namespace pt = boost::property_tree;

#define SLEIGH_VERSION 4
#define SLA_SUCCESS (0)
#define NOT_INITIALIZED (-1)

typedef struct _DECISION_PAIR
{
    unsigned int id;
    unsigned int off;
    unsigned int nonzero;
    unsigned int mask;
    unsigned int val;
} DECISION_PAIR, *PDECISION_PAIR;

typedef struct _BIT_PATTERN
{
    unsigned int start_bit;
    unsigned int end_bit;
    string pattern_type;
    string pattern;

} BIT_PATTERN, *PBIT_PATTERN;

typedef struct _TOKENFIELD
{
    bool bigendian;
    bool signbit;
    unsigned int startbit;
    unsigned int endbit;
    unsigned int startbyte;
    unsigned int endbyte;
    unsigned int shift;

} TOKENFIELD, *PTOKENFIELD;

typedef struct _varlist_sym
{
    unsigned int id;
    TOKENFIELD bitfield;
    vector<unsigned int> register_ids;
} varlist_sym, *pvarlist_sym;

typedef struct _OPERAND_SYM
{
    unsigned int id;
    TOKENFIELD bitfield;
} OPERAND_SYM, *POPERAND_SYM;

typedef struct _CONSTRUCTOR_PIECE
{
    string type; // print or opprint
    unsigned int id; // needed for opprint
    string part;
} CONSTRUCTOR_PIECE, *PCONSTRUCTOR_PIECE;

typedef struct _CONSTRUCTOR
{
    unsigned int id;
    unsigned int constructor_length; // length of the instruction in bytes
    unsigned int source_file;
    unsigned int line_number;
    vector<CONSTRUCTOR_PIECE> constructor_pieces;
    vector<BIT_PATTERN> bit_patterns;
} CONSTRUCTOR, *PCONSTRUCTOR;

class Slautil
{
    public:
        Slautil();

        int loadSla(const string& filename);
        int getRegisters(vector<string>& registers);

        // various way to look up instructions
        int getConstructorCount(unsigned int& count);
        int getConstructorText(unsigned int id, string& constructor_text);
        int getConstructorBitPattern(unsigned int id, string& bit_pattern);
        int getConstructorTextByBitPattern(const string& bit_pattern,
                                           string& constructor_text);
        int getConstructorIdByBitPattern(const string& bit_pattern,
                                         unsigned int& id);
        int getConstructorTextRegisterById(unsigned int id,
                                           string& register_name,
                                           unsigned int register_number,
                                           string& bit_pattern);

    private:
        int loadSlaXML(const string& filename);

        // parsing fields within the xml
        int parseRegisters(void);
        int parseVars(void);
        int parseSubtableSymHeads(void);
        int parseConstructors(void);
        int parseVarlistSym(void);
        int parseOperandSyms(void);
        int parseDecisionPairs(void);
        int convertDecisionPairsToBitPatterns(void);
        int recursiveParseDecisionPairs(const boost::property_tree::ptree & subtree);
        int parseDecisionPair(const boost::property_tree::ptree& subtree);
        int addNonOpcodeBitPatterns(void);

        // various helper routines
        int getConstructorText(unsigned int id,
                               string& constructor_text,
                               bool use_bitpattern,
                               const string& bit_pattern);
        int checkSubsym(unsigned int& id);
        int countAdjacentOnes(unsigned int id,
                              unsigned int mask,
                              unsigned int value);
        string extractBits(unsigned int start_bit,
                           unsigned int number_of_bits,
                           unsigned int value);
        int addBitPattern(CONSTRUCTOR& curr_constructor,
                          const TOKENFIELD& bitfield,
                          const string& type,
                          unsigned int count);
        int compareBitPatterns(const string& a, const string& b);
        int convertBitFieldToValue(TOKENFIELD& bitfield,
                                   const string& bit_pattern,
                                   unsigned int& value);

        // member vars
        boost::unordered_map<unsigned int, varlist_sym> m_varlist_syms;
        boost::unordered_map<unsigned int, OPERAND_SYM> m_operand_syms;
        boost::unordered_map<unsigned int, unsigned int> m_subsyms;
        boost::unordered_map<unsigned int, string> m_vars;
        vector<CONSTRUCTOR> m_constructors;
        vector<DECISION_PAIR> m_decision_pairs;
        vector<string> m_registers;
        unsigned int m_constructor_count;
        unsigned int m_sleigh_version;
        pt::ptree m_tree;
        bool m_initialized;
};
