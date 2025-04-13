//-----------------------------------------------------------------------------
// File: slautil.cpp
//
// Misc helper functions for working with .sla files
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <string>
#include <iostream>
#include <fstream>
#include "slautil.h"

using namespace std;
namespace pt = boost::property_tree;

// sorting bit_patterns by start_bit
struct less_than_key
{
    inline bool operator() (const BIT_PATTERN& a, const BIT_PATTERN& b)
    {
        return (b.start_bit < a.start_bit);
    }
};

// default constructor
Slautil::Slautil(void)
{
    m_initialized = false;
}

// load the processor module file
// currently only supports XML .sla files
int Slautil::loadSla(const string& filename)
{
    int status = 0;

    status = this->loadSlaXML(filename);
    if(status != SLA_SUCCESS)
    {
        return status;
    }

    m_initialized = true;
    return SLA_SUCCESS;
}

// return the registers from the processor module
int Slautil::getRegisters(vector<string>& registers)
{
    if(!m_initialized)
    {
        return NOT_INITIALIZED;
    }

    registers.reserve(m_registers.size());
    std::copy(m_registers.begin(),
              m_registers.end(),
              std::back_inserter(registers));

    return SLA_SUCCESS;
}

// get the number of instructions (constructors) in the processor module
int Slautil::getConstructorCount(unsigned int& count)
{
    if(!m_initialized)
    {
        return NOT_INITIALIZED;
    }

    count = m_constructors.size();
    return SLA_SUCCESS;
}

// generate the opcode bit patterns for immediates and registers
int Slautil::addNonOpcodeBitPatterns(void)
{
    for(unsigned int i = 0; i < m_constructors.size(); i++)
    {
        unsigned int num_immediates = 0;
        unsigned int num_registers = 0;

        PCONSTRUCTOR curr_constructor = &m_constructors[i];

        // TODO; cleanup function

        for(unsigned int j = 0;
            j < curr_constructor->constructor_pieces.size();
            j++)
        {
            PCONSTRUCTOR_PIECE curr_constructor_piece = NULL;

            curr_constructor_piece = &curr_constructor->constructor_pieces[j];

            if(curr_constructor_piece->type == "opprint")
            {
                boost::unordered_map<unsigned int, varlist_sym> ::iterator itr;
                boost::unordered_map<unsigned int, OPERAND_SYM> ::iterator itr2;

                //cout << curr_constructor_piece->id << endl;

                itr = m_varlist_syms.find(curr_constructor_piece->id);
                if(itr == m_varlist_syms.end())
                {
                    itr2 = m_operand_syms.find(curr_constructor_piece->id);
                    if(itr2 == m_operand_syms.end())
                    {
                        boost::unordered_map<unsigned int, string> ::iterator itr3;

                        itr3 = m_vars.find(curr_constructor_piece->id);
                        if(itr3 == m_vars.end())
                        {
                            cout << "Failed to find " << curr_constructor_piece->id << endl;
                            throw 1;
                            continue;
                        }

                        if(std::find(m_registers.begin(), m_registers.end(), itr3->second) != m_registers.end())
                        {
                            num_registers++;
                            continue;
                        }
                        else
                        {
                            cout << "What the heck should never get here!! " << itr3->second << endl;
                            throw 4;
                        }

                        throw 1;
                        continue;
                    }

                    // found operand_syms
                    addBitPattern(m_constructors[i],
                                  itr2->second.bitfield,
                                  "imm",
                                  num_immediates);
                    num_immediates++;
                    continue;
                }

                addBitPattern(m_constructors[i],
                             itr->second.bitfield,
                             "reg",
                             num_registers);
                num_registers++;
                continue;
            }
        } // for(unsigned int j = 0; j < curr_constructor->constructor_pieces.size(); j++)

        // sort the bit patterns
        std::sort(curr_constructor->bit_patterns.begin(),
                  curr_constructor->bit_patterns.end(),
                  less_than_key());
    }

    return SLA_SUCCESS;
}

// adds a bit pattern to a constructor
int Slautil::addBitPattern(CONSTRUCTOR& curr_constructor,
                           const TOKENFIELD& bitfield,
                           const string& type,
                           unsigned int count)
{
    BIT_PATTERN curr_bit_pattern;
    unsigned char patternChar = '\x0';

    if(count >= 25)
    {
        return -1;
    }

    curr_bit_pattern.start_bit = bitfield.startbit;
    curr_bit_pattern.end_bit = bitfield.endbit;
    curr_bit_pattern.pattern_type = type;

    if(type == "imm")
    {
        patternChar = 'a' + count;
    }
    else if(type == "reg")
    {
        patternChar = 'A' + count;
    }
    else
    {
        patternChar = '?';
    }

    for(unsigned int i = curr_bit_pattern.start_bit;
       i <= curr_bit_pattern.end_bit;
       i++)
    {
        curr_bit_pattern.pattern += patternChar;
    }

    curr_constructor.bit_patterns.push_back(curr_bit_pattern);

    return SLA_SUCCESS;
}

// get the opcode bit pattern given an constructor id
int Slautil::getConstructorBitPattern(unsigned int id, string& bit_pattern)
{
    PCONSTRUCTOR curr_constructor = NULL;
    unsigned int size = 0;

    if(id >= m_constructors.size())
    {
        cout << "Bad ID!!" << endl;
        return -2;
    }

    curr_constructor = &m_constructors[id];
    bit_pattern = "";

    for(unsigned int k = 0; k < curr_constructor->bit_patterns.size(); k++)
    {
        PBIT_PATTERN curr_bit_pattern = &curr_constructor->bit_patterns[k];

        //bit_pattern += curr_bit_pattern->pattern_type + "_" + to_string(curr_bit_pattern->start_bit) + "_" + to_string(curr_bit_pattern->end_bit) + "=";

        if(curr_bit_pattern->pattern_type == "opcode")
        {
            bit_pattern += curr_constructor->bit_patterns[k].pattern;
        }
        else if(curr_bit_pattern->pattern_type == "reg")
        {
            size = curr_bit_pattern->end_bit -
                   curr_bit_pattern->start_bit + 1;
            bit_pattern += string(size, curr_bit_pattern->pattern[0]);
        }
        else if(curr_bit_pattern->pattern_type == "imm")
        {
            size = curr_bit_pattern->end_bit -
                   curr_bit_pattern->start_bit + 1;
            bit_pattern += string(size, curr_bit_pattern->pattern[0]);
        }
    }

    // sanity check the bit pattern size
    if(bit_pattern.size() == 0)
    {
        return -1;
    }

    return SLA_SUCCESS;
}

// get the instruction mnemonic given a constructor id
int Slautil::getConstructorText(unsigned int id, string& constructor_text)
{
    string unused;
    return getConstructorText(id, constructor_text, false, unused);
}

// get the instruction mnemonic given a constructor id
int Slautil::getConstructorText(unsigned int id,
                                string& constructor_text,
                                bool use_bit_pattern,
                                const string& bit_pattern)
{
    PCONSTRUCTOR curr_constructor = NULL;

    if(!m_initialized)
    {
        return NOT_INITIALIZED;
    }

    if(id >= m_constructors.size())
    {
        cout << "Bad ID!!" << endl;
        return -2;
    }

    curr_constructor = &m_constructors[id];
    constructor_text = "";

    for(unsigned int j = 0; j < curr_constructor->constructor_pieces.size(); j++)
    {
        PCONSTRUCTOR_PIECE curr_constructor_piece = NULL;

        curr_constructor_piece = &curr_constructor->constructor_pieces[j];

        if(curr_constructor_piece->type == "print")
        {
            constructor_text += curr_constructor_piece->part;
        }
        else if(curr_constructor_piece->type == "opprint")
        {
            //cout << curr_constructor_piece->type << endl;
            //cout << curr_constructor_piece->id << endl;

            // todo change logic
            boost::unordered_map<unsigned int, varlist_sym> ::iterator itr;
            boost::unordered_map<unsigned int, OPERAND_SYM> ::iterator itr2;

            itr = m_varlist_syms.find(curr_constructor_piece->id);
            if(itr == m_varlist_syms.end())
            {
                itr2 = m_operand_syms.find(curr_constructor_piece->id);
                if(itr2 == m_operand_syms.end())
                {
                    boost::unordered_map<unsigned int, string> ::iterator itr3;
                    itr3 = m_vars.find(curr_constructor_piece->id);

                    if(itr3 == m_vars.end())
                    {
                        cout << "Failed to find " << curr_constructor_piece->id << endl;
                        throw 1;
                        continue;
                    }

                    constructor_text += itr3->second;
                    continue;
                }
                else
                {
                    if(use_bit_pattern == false)
                    {
                        constructor_text += "__immediate_list__";
                    }
                    else
                    {
                        unsigned int value = 0;
                        convertBitFieldToValue(itr2->second.bitfield,
                                               bit_pattern,
                                               value);

                        stringstream ss;
                        ss << setbase(16) << value;

                        constructor_text += "0x" + ss.str();
                    }
                }

                continue;
            }
            else
            {
                if(use_bit_pattern == false)
                {
                    constructor_text += "__register_list__";
                }
                else
                {
                    unsigned int register_index = 0;
                    convertBitFieldToValue(itr->second.bitfield,
                                           bit_pattern,
                                           register_index);

                    if(register_index < itr->second.register_ids.size())
                    {
                        boost::unordered_map<unsigned int, string> ::iterator itr3;
                        itr3 = m_vars.find(itr->second.register_ids[register_index]);

                        constructor_text += itr3->second;
                    }
                    else
                    {
                        constructor_text += "___ERROR_REGISTER__INDEX__";
                    }
                }
            }
        }
    } // for(unsigned int j = 0; j < curr_constructor->constructor_pieces.size(); j++)

    return SLA_SUCCESS;
}

// get the constructor register by id
int Slautil::getConstructorTextRegisterById(unsigned int id,
                                            string& register_name,
                                            unsigned int register_number,
                                            string& bit_pattern)
{
    PCONSTRUCTOR curr_constructor = NULL;
    unsigned int registers_count = 0;

    // TODO: sloppy, add error handling

    if(!m_initialized)
    {
        return NOT_INITIALIZED;
    }

    if(id >= m_constructors.size())
    {
        cout << "Bad ID!!" << endl;
        return -2;
    }

    curr_constructor = &m_constructors[id];
    register_name = "";

    for(unsigned int j = 0;
        j < curr_constructor->constructor_pieces.size();
        j++)
    {
        PCONSTRUCTOR_PIECE curr_constructor_piece = NULL;
        curr_constructor_piece = &curr_constructor->constructor_pieces[j];

        if(curr_constructor_piece->type == "opprint")
        {
            // todo change logic
            boost::unordered_map<unsigned int, varlist_sym> ::iterator itr;
            boost::unordered_map<unsigned int, OPERAND_SYM> ::iterator itr2;

            itr = m_varlist_syms.find(curr_constructor_piece->id);
            if(itr != m_varlist_syms.end())
            {
                if(registers_count != register_number)
                {
                    registers_count++;
                    continue;
                }

                unsigned int register_index = 0;

                /*
                cout << "itr->second.bitfield " << &itr->second.bitfield << endl;
                cout << "bitpattern " << bit_pattern << endl;
                cout << "regindex " << register_index << endl;
                */

                convertBitFieldToValue(itr->second.bitfield,
                                       bit_pattern,
                                       register_index);

                if(register_index < itr->second.register_ids.size())
                {
                    boost::unordered_map<unsigned int, string> ::iterator itr3;
                    itr3 = m_vars.find(itr->second.register_ids[register_index]);
                    register_name += itr3->second;
                    return 0;
                }
                else
                {
                    cout << "bad bad bad" << endl;
                    register_name += "___ERROR_REGISTER__INDEX__";
                    cout << register_name << endl;
                    throw 1;
                    return 0;
                }
            }

            boost::unordered_map<unsigned int, string> ::iterator itr3;
            itr3 = m_vars.find(curr_constructor_piece->id);
            if(itr3 == m_vars.end())
            {
                cout << "Failed to find " << curr_constructor_piece->id << endl;
                throw 1;
                continue;
            }
            else
            {
                if(std::find(m_registers.begin(), m_registers.end(), itr3->second) != m_registers.end())
                {
                    if(registers_count == register_number)
                    {
                        register_name = itr3->second;
                        //cout << "FOUND " << register_name << endl;
                        //throw 1;
                        return 0;
                    }

                    registers_count++;
                    continue;
                }
                continue;
            }
        }
        else if(curr_constructor_piece->type == "print")
        {
            // TODO:
            // BUGBUG: incorrect hack
            if(curr_constructor_piece->part[0] == 'r' &&
               curr_constructor_piece->part[1] == '0')
            {
                //cout << "print: " << curr_constructor_piece->part << endl;

                if(registers_count == register_number)
                {
                    register_name = "r0";
                    //cout << "FOUND " << register_name << endl;
                    return 0;
                }

                registers_count++;
                continue;
            }
        }
    }

    // TODO; should never get here
    cout << "RC " << registers_count << "  register_number " << register_number << endl;
    cout << "Failing here" << endl;
    return -1;
}

// get a constructor mnemonic via opcode bit string
int Slautil::getConstructorTextByBitPattern(const string& bit_pattern,
                                            string& constructor_text)
{
    unsigned int id = 0;
    int result = 0;

    result = getConstructorIdByBitPattern(bit_pattern, id);
    if(result != 0)
    {
        //cout << "Failed to find bit pattern" << endl;
        return result;
    }

    result = getConstructorText(id, constructor_text, true, bit_pattern);
    if(result != 0)
    {
        //cout << "Failed to get constructor text" << endl;
        return result;
    }

    return SLA_SUCCESS;
}

// get a constructor ID by opcode bit string
int Slautil::getConstructorIdByBitPattern(const string& bit_pattern,
                                          unsigned int& id)
{
    unsigned int count;
    int result = 0;
    id = 0xffffffff;

    if(!m_initialized)
    {
        return NOT_INITIALIZED;
    }

    result = this->getConstructorCount(count);
    if(result != 0)
    {
        cout << "Failed to get constructor count" << endl;
        return result;
    }

    for(unsigned int i = 0; i < count; i++)
    {
        string bit_pattern2;
        result = this->getConstructorBitPattern(i, bit_pattern2);
        if(result != 0)
        {
            cout << "Failed to get bit pattern" << endl;
            return result;
        }

        result = this->compareBitPatterns(bit_pattern, bit_pattern2);
        if(result == 0)
        {
            if(id != 0xffffffff)
            {
                //cout << "Found duplicate!!" << endl;
                //return -1;
            }
            id = i;
        }
    }

    if(id != 0xffffffff)
    {
        return SLA_SUCCESS;
    }

    return -1;
}

// compare two opcode bit patterns
// has fuzzy logic for combined fields
int Slautil::compareBitPatterns(const string& a, const string& b)
{
    bool a_is_digit = true;
    bool b_is_digit = true;

    if(a.size() != b.size())
    {
        return -1;
    }

    for(unsigned int i = 0; i < a.size(); i++)
    {
        a_is_digit = ((a[i] == '0') || (a[i] == '1'));
        b_is_digit = ((b[i] == '0') || (b[i] == '1'));

        if(a_is_digit != b_is_digit)
        {
            // one is a digit, the other isn't
            // this is fine
            continue;
        }

        // both are digits or non-digits
        // must be the same
        if(a[i] != b[i])
        {
            return -1;
        }
    }

    return 0;
}

// converts a bit field into a value
int Slautil::convertBitFieldToValue(TOKENFIELD& bitfield,
                                    const string& bit_pattern,
                                    unsigned int& value)
{
    value = 0;

    unsigned int bit_pattern_end = bit_pattern.length();

    if(bitfield.startbit >= bit_pattern_end ||
       bitfield.endbit >= bit_pattern_end)
    {
        cout << "Invalid bit field\bit pattern combination!!" << endl;
        throw 2;
    }

    for(unsigned int i = bitfield.startbit; i <= bitfield.endbit; i++)
    {
        unsigned int bit_pos = i - bitfield.startbit;

        if(bit_pattern[bit_pattern_end - i - 1] == '1')
        {
            value += (1 << bit_pos);
        }
        else if(bit_pattern[bit_pattern_end - i - 1] == '0')
        {
            // don't do anything for zero
        }
        else
        {
            // TODO fix
            cout << "Unexpected bit string val!!" << endl;
            throw 1;
        }
    }

    return 0;
}
