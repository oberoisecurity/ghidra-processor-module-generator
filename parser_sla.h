//-----------------------------------------------------------------------------
// File: parser_sla.h
//
// Parsing and combining the instructions from .sla
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#pragma once

#include <iostream>
#include <set>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/regex.hpp>
#include "instruction.h"
using namespace std;

int parseInstructionsSla(PARSED_DATA& parsedData, unsigned int fileId);
