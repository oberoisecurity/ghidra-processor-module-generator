//-----------------------------------------------------------------------------
// File: slautil.h
//
// Parsing XML SLA files
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

// load the XML SLA processor module
int Slautil::loadSlaXML(const string& filename)
{
    // Parse the XML into the property tree.
    try
    {
        pt::read_xml(filename, m_tree);
    }
    catch(...)
    {
        cout << "[-] Exception when opening sla (" << filename << ")!" << endl;
        return -1;
    }

    m_sleigh_version = m_tree.get("sleigh.<xmlattr>.version", 0);
    if(m_sleigh_version != SLEIGH_VERSION)
    {
        cout << "[-] Invalid sleigh version (" << m_sleigh_version << ")!" << endl;
        cout << "[-] Is the .sla file correct?" << endl;
        return -1;
    }

    this->parseVars();
    this->parseSubtableSymHeads();
    this->parseOperandSyms();
    this->parseConstructors();
    this->parseDecisionPairs();
    this->convertDecisionPairsToBitPatterns();
    this->parseVarlistSym();
    this->parseRegisters(); // TODO: needs to happen before add_non_opcode_bit_patterns()
    this->addNonOpcodeBitPatterns();

    return SLA_SUCCESS;
}

// read the variables from the processor module
int Slautil::parseVars(void)
{
    for(auto &v : m_tree.get_child("sleigh.symbol_table"))
    {
        if(v.first != "varnode_sym_head" &&
           v.first != "value_sym_head" &&
           v.first != "operand_sym_head")
        {
            continue;
        }

        // todo can throw
        std::string name = v.second.get_child("<xmlattr>.name").data();
        std::string id_str = v.second.get_child("<xmlattr>.id").data();

        unsigned int id = stoi(id_str, 0, 0x10);

        m_vars.emplace(id, name);
    }

    return SLA_SUCCESS;
}

// read the subtable sym heads from the processor module
int Slautil::parseSubtableSymHeads(void)
{
    for(auto &v : m_tree.get_child("sleigh.symbol_table"))
    {
        size_t pos = 0;

        if(v.first != "subtable_sym_head")
        {
            continue;
        }

        // todo can throw
        std::string name = v.second.get_child("<xmlattr>.name").data();
        std::string id_str = v.second.get_child("<xmlattr>.id").data();

        // silly workaround to support instructions that reference the same reg more than once
        pos = name.find("_dup");
        if (pos == std::string::npos)
        {
            continue;
        }

        name.resize(pos);

        unsigned int id = stoi(id_str, 0, 0x10);
        m_vars.emplace(id, name);
    }

    return SLA_SUCCESS;
}

// read the operand syms from the processor module
int Slautil::parseOperandSyms(void)
{
    for(auto &operand_sym_node : m_tree.get_child("sleigh.symbol_table"))
    {
        OPERAND_SYM curr_operand_sym;
        std::string var_subsym_id_str;
        std::string var_id_str;

        if(operand_sym_node.first != "operand_sym")
        {
            continue;
        }

        var_id_str = operand_sym_node.second.get("<xmlattr>.id", "");
        if(var_id_str == "")
        {
            continue;
        }
        unsigned int var_id = stoi(var_id_str, 0, 0x10);

        var_subsym_id_str = operand_sym_node.second.get("<xmlattr>.subsym", "");
        if(var_subsym_id_str != "")
        {
            unsigned int var_subsym_id = stoi(var_subsym_id_str, 0, 0x10);
            m_subsyms[var_id] = var_subsym_id;
            continue;
        }

        curr_operand_sym.id = var_id;
        curr_operand_sym.bitfield.startbit = operand_sym_node.second.get("tokenfield.<xmlattr>.startbit", 0);
        curr_operand_sym.bitfield.endbit = operand_sym_node.second.get("tokenfield.<xmlattr>.endbit", 0);
        curr_operand_sym.bitfield.startbyte = operand_sym_node.second.get("tokenfield.<xmlattr>.startbyte", 0);
        curr_operand_sym.bitfield.endbyte = operand_sym_node.second.get("tokenfield.<xmlattr>.endbyte", 0);
        curr_operand_sym.bitfield.shift = operand_sym_node.second.get("tokenfield.<xmlattr>.shift", 0);

        m_operand_syms[curr_operand_sym.id] = curr_operand_sym;
    }

    return SLA_SUCCESS;
}

// read the instruction constructors from the processor module
int Slautil::parseConstructors(void)
{
    m_constructor_count = m_tree.get("sleigh.symbol_table.subtable_sym.<xmlattr>.numct", 0);

    for(auto &constructor_node : m_tree.get_child("sleigh.symbol_table.subtable_sym"))
    {
        CONSTRUCTOR temp_constructor = {};
        vector<unsigned int> ids;

        if(constructor_node.first != "constructor")
        {
            continue;
        }

        temp_constructor.constructor_length = constructor_node.second.get("<xmlattr>.length", 0);
        temp_constructor.source_file = constructor_node.second.get("<xmlattr>.source", 0);
        temp_constructor.line_number = constructor_node.second.get("<xmlattr>.line", 0);

        // todo: should we check constructor.parent = 0?

        for(auto &constructor_node_child : constructor_node.second)
        {
            if(constructor_node_child.first == "<xmlattr>")
            {
                continue;
            }
            else if(constructor_node_child.first == "construct_tpl")
            {
                continue;
            }
            else if(constructor_node_child.first == "oper")
            {
                string id_str;
                unsigned int id = 0;

                id_str = constructor_node_child.second.get("<xmlattr>.id", "");
                id = stoi(id_str, NULL, 0x10);
                ids.push_back(id);
            }
            else if(constructor_node_child.first == "print")
            {
                CONSTRUCTOR_PIECE temp_constructor_piece;

                temp_constructor_piece.type = "print";
                temp_constructor_piece.id = -1;
                temp_constructor_piece.part = constructor_node_child.second.get("<xmlattr>.piece", "");

                temp_constructor.constructor_pieces.push_back(temp_constructor_piece);
            }
            else if(constructor_node_child.first == "opprint")
            {
                string id_str;
                unsigned int id = 0;
                unsigned int id2 = 0;

                id_str = constructor_node_child.second.get("<xmlattr>.id", "");
                id = stoi(id_str);

                CONSTRUCTOR_PIECE temp_constructor_piece;

                id2 = ids[id];

                checkSubsym(id2);

                string var = m_vars[id2];

                temp_constructor_piece.type = "opprint";
                temp_constructor_piece.id = id2;
                temp_constructor_piece.part = var;

                // part??

                temp_constructor.constructor_pieces.push_back(temp_constructor_piece);
            }
            else
            {
                cout << "Unknown constructor node child: " << constructor_node_child.first << endl;
                return -2;
            }
        }
        m_constructors.push_back(temp_constructor);
    }

    if(m_constructor_count != m_constructors.size())
    {
        cout << "Invalid constructors: " << m_constructor_count << " " << m_constructors.size() << endl;
        return -2;
    }

    return SLA_SUCCESS;
}

// parse the decision pairs from the processor module
// decision pairs are used to differentiate instructions via their opcode
int Slautil::parseDecisionPairs(void)
{
    m_decision_pairs.resize(m_constructor_count);

    const boost::property_tree::ptree & subtree = m_tree.get_child("sleigh.symbol_table.subtable_sym.decision");
    this->recursiveParseDecisionPairs(subtree);

    return SLA_SUCCESS;
}

// decision pairs can be recursively defined
int Slautil::recursiveParseDecisionPairs(const boost::property_tree::ptree& subtree)
{
    //TODO: why use boost foreach??
    for(auto &v : subtree)
    {
        if(v.first == "decision")
        {
            this->recursiveParseDecisionPairs(v.second);
        }
        else if(v.first == "pair")
        {
            this->parseDecisionPair(v.second);
        }
        else if(v.first == "<xmlattr>")
        {
            continue;
        }
        else
        {
            cout << "Unknown value!!" << v.first << endl;
            return -1;
        }
    }

    return 0;
}

// parse an individual decision pair
int Slautil::parseDecisionPair(const boost::property_tree::ptree& subtree)
{
    DECISION_PAIR decision_pair = {};

    // todo error checking
    decision_pair.id = subtree.get("<xmlattr>.id", 0);
    decision_pair.off = subtree.get("instruct_pat.pat_block.<xmlattr>.off", 0);
    decision_pair.nonzero = subtree.get("instruct_pat.pat_block.<xmlattr>.nonzero", 0);
    string mask = subtree.get("instruct_pat.pat_block.mask_word.<xmlattr>.mask", "");
    string val = subtree.get("instruct_pat.pat_block.mask_word.<xmlattr>.val", "");

    decision_pair.mask = stol(mask, NULL, 0x10);
    decision_pair.val = stol(val, NULL, 0x10);

    m_decision_pairs[decision_pair.id] = decision_pair;

    return 0;
}

// convert the decision pairs into opcode bit patterns
int Slautil::convertDecisionPairsToBitPatterns(void)
{
    for(unsigned int i = 0; i < m_constructors.size(); i++)
    {
        //cout << i << ")" << endl;
        unsigned int constructor_length = 0;
        PDECISION_PAIR curr_decision_pair = NULL;
        unsigned int shift_value = 0;
        unsigned int mask = 0;
        unsigned int value = 0;

        curr_decision_pair = &m_decision_pairs[i];
        constructor_length = m_constructors[i].constructor_length;

        //cout << curr_decision_pair->id << " " << curr_decision_pair->mask << " " << curr_decision_pair->val << endl;

        if(curr_decision_pair->nonzero > 4)
        {
            cout << "Invalid decision nonzero amount!!" << endl;
            return -3;
        }

        if(constructor_length <= curr_decision_pair->off)
        {
            cout << "Invalid decision offset amount!!" << endl;
            return -4;
        }

        shift_value = curr_decision_pair->off * 8;
        mask = curr_decision_pair->mask >> shift_value;
        value = curr_decision_pair->val >> shift_value;

        countAdjacentOnes(i, mask, (value & mask));
    }

    return SLA_SUCCESS;
}

// read the varlist syms from the processor module
int Slautil::parseVarlistSym(void)
{
    for(auto &varlist_sym_node : m_tree.get_child("sleigh.symbol_table"))
    {
        varlist_sym curr_varlist_sym;

        if(varlist_sym_node.first != "varlist_sym")
        {
            continue;
        }

        //cout << varlist_sym_node.first  << endl;

        std::string id_str = varlist_sym_node.second.get("<xmlattr>.id", "");
        curr_varlist_sym.id = stoi(id_str, 0, 0x10);

        curr_varlist_sym.bitfield.startbit = varlist_sym_node.second.get("tokenfield.<xmlattr>.startbit", 0);
        curr_varlist_sym.bitfield.endbit = varlist_sym_node.second.get("tokenfield.<xmlattr>.endbit", 0);
        curr_varlist_sym.bitfield.startbyte = varlist_sym_node.second.get("tokenfield.<xmlattr>.startbyte", 0);
        curr_varlist_sym.bitfield.endbyte = varlist_sym_node.second.get("tokenfield.<xmlattr>.endbyte", 0);
        curr_varlist_sym.bitfield.shift = varlist_sym_node.second.get("tokenfield.<xmlattr>.shift", 0);

        //cout << curr_varlist_sym.bitfield.startbit  << " " <<  curr_varlist_sym.bitfield.endbit << endl;

        for(auto &var_node : varlist_sym_node.second)
        {
            if(var_node.first != "var")
            {
                continue;
            }

            std::string var_id_str = var_node.second.get("<xmlattr>.id", "");
            unsigned int var_id = stoi(var_id_str, 0, 0x10);
            curr_varlist_sym.register_ids.push_back(var_id);

        }

        m_varlist_syms[curr_varlist_sym.id] = curr_varlist_sym;
    }

    return SLA_SUCCESS;
}

// read the registers from the processor module
int Slautil::parseRegisters(void)
{
    for(auto &v : m_tree.get_child("sleigh.symbol_table"))
    {
        if(v.first != "varnode_sym")
        {
            continue;
        }

        // TODO: throws if missing
        std::string space = v.second.get_child("<xmlattr>.space").data();
        if(space != "register")
        {
            continue;
        }
        //cout << space << endl;

        std::string id_str = v.second.get_child("<xmlattr>.id").data();

        unsigned int id = stoi(id_str, 0, 0x10);

        boost::unordered_map<unsigned int, std::string> ::iterator itr;

        itr = m_vars.find(id);
        if(itr == m_vars.end())
        {
            cout << "Failed to find " << id << "!!" << endl;
            return -1;
        }

        m_registers.push_back(itr->second);
    }

    return 0;
}

// helper function to count the number of adjacent ones in a bitmask
int Slautil::countAdjacentOnes(unsigned int id,
                               unsigned int mask,
                               unsigned int value)
{
    unsigned int count = 0;

    for(unsigned int i = 0; i < 32; i++)
    {
        bool bit_on = (mask & (1 << i));

        if(bit_on)
        {
            count += 1;
        }

        if(!bit_on)
        {
            if(count != 0)
            {
                BIT_PATTERN temp_bit_pattern;

                /*
                cout << "opcode_";
                cout << (i - count);
                cout << "_";
                cout << (i - 1);
                cout << "= " << endl;
                */

                // TODO: make this a func
                temp_bit_pattern.pattern_type = "opcode";
                temp_bit_pattern.start_bit = i - count;
                temp_bit_pattern.end_bit = i - 1;
                temp_bit_pattern.pattern = extractBits(temp_bit_pattern.start_bit,
                                                       temp_bit_pattern.end_bit,
                                                       value);

                m_constructors[id].bit_patterns.push_back(temp_bit_pattern);
            }
            count = 0;
        }
    }

    if(count != 0)
    {
        BIT_PATTERN temp_bit_pattern;

        /*
        cout << "opcode_";
        cout << (32 - count);
        cout << "_";
        cout << (32 - 1);
        cout << "= " << endl;
        */

        // TODO: make this a func
        temp_bit_pattern.pattern_type = "opcode";
        temp_bit_pattern.start_bit = 33 - count - 1;
        temp_bit_pattern.end_bit = 32 - 1;
        temp_bit_pattern.pattern = extractBits(temp_bit_pattern.start_bit,
                                               temp_bit_pattern.end_bit,
                                                value);

        m_constructors[id].bit_patterns.push_back(temp_bit_pattern);
    }

    return SLA_SUCCESS;
}

// convert a number into a bit string
string Slautil::extractBits(unsigned int start_bit,
                            unsigned int end_bit,
                            unsigned int value)
{
    string bit_string = "";

    for(unsigned int i = start_bit; i <= end_bit; i++)
    {
        if(value & (1 << i))
        {
            bit_string.insert(0, 1, '1');
        }
        else
        {
            bit_string.insert(0, 1, '0');
        }
    }

    if(bit_string.length() == 0)
    {
        cout << "Invalid extract bits!!" << endl;
        cout << start_bit << " " << end_bit << endl;
        throw 1;
    }

    return bit_string;
}

// remap a subsym if necessary
int Slautil::checkSubsym(unsigned int& id)
{
    boost::unordered_map<unsigned int, unsigned int> ::iterator itr;
    itr = m_subsyms.find(id);
    if(itr == m_subsyms.end())
    {
        return -3;
    }

    //cout << "replace " << id << " with " << itr->second << endl;
    id = itr->second;

    return SLA_SUCCESS;
}
