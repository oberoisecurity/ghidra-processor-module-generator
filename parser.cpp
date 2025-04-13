//-----------------------------------------------------------------------------
// File: parser.cpp
//
// Parsing instructions from disassembly text file
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------
#include <boost/timer/timer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "parser.h"
#include "registers.h"
#include "thread_pool.h"

const boost::regex g_opcodeRegex{"0[xX][0-9a-fA-F]+"};
const boost::regex g_integerRegex{"\\d+"};

// used to track if we have a variable length instruction set
static bool g_opcodeSize[4] = {false, false, false, false};

set<string> g_allRegisters;
extern const char* ALL_REGISTERS[];

static bool splitChar(char ch);
static bool isCharWhiteSpace(char ch);
static int splitDisassemblyLine(vector<string>& lineSplit, const string& line);
static void updateOpcodeSize(unsigned int opcodeSize);
static bool hasVariableLengthOpcodes(void);

static int parseInstructionsWorker(PARSED_DATA& parsedData,
                                   const char* buffer,
                                   unsigned long long start,
                                   unsigned long long end);
static int parseInstructionsParser(PARSED_DATA& parsedData,
                                   unsigned int lineNum,
                                   string& line,
                                   set<string>& registers,
                                   set<string>& mnemonics,
                                   map<string, Instruction*>& allInstructions);

// helper to convert number of opcode bits to to index into tokenInstructions array
int convertOpcodeSizeToIndex(unsigned int opcodeSizeInBits)
{
    switch(opcodeSizeInBits)
    {
        // bits to index into tokenInsructions array
        case 8:
            return 0;
        case 16:
            return 1;
        case 24:
            return 2;
        case 32:
            return 3;
        default:
            cout << "[-] convertOpcodeSizeToIndex: Invalid opcode size (" << opcodeSizeInBits << ") specified!!" << endl;
            throw 1;
    }

    // never get here, will throw in default case of switch statement
    return -1;
}

// check which opcode sizes we have seen during parsing
static void updateOpcodeSize(unsigned int opcodeSizeInBits)
{
    switch(opcodeSizeInBits)
    {
        case 8:
            g_opcodeSize[0] = true;
            break;
        case 16:
            g_opcodeSize[1] = true;
            break;
        case 24:
            g_opcodeSize[2] = true;
            break;
        case 32:
            g_opcodeSize[3] = true;
            break;
        default:
            cout << "[-] updateOpcodeSize: Invalid opcode size (" << opcodeSizeInBits << ") specified!!" << endl;
            break;
    }
}

// returns true if the parsed architecture has variable length opcodes
// supported opcode lengths are 1-4 bytes
static bool hasVariableLengthOpcodes(void)
{
    unsigned int count = 0;

    for(unsigned int i = 0; i < sizeof(g_opcodeSize)/sizeof(g_opcodeSize[0]); i++)
    {
        if(g_opcodeSize[i] == true)
        {
            count++;
        }
    }

    if(count > 1)
    {
        return true;
    }

    return false;
}

// Load all the registers extracted from Ghidra into a set
// When parsing the instructions this is how we will tell the difference
// between an instruction mnemonic versus a register
int initRegisters(void)
{
    for(unsigned int i = 0;
        i < sizeof(ALL_REGISTERS)/sizeof(ALL_REGISTERS[0]);
        i++)
    {
        g_allRegisters.insert(ALL_REGISTERS[i]);
    }

    return 0;
}

// additionalRegisters is a list of additional registers specified by the user
// at the command line or queried from the .sla file
int addRegisters(vector<string>& additionalRegisters)
{
    for(auto additionalRegister : additionalRegisters)
    {
        g_allRegisters.insert(additionalRegister);
    }

    return 0;
}

// Returns true if the passed in string is a register. This is determined 
// seeing if it's in the g_allRegisters set
bool isRegister(const string& str)
{
    set<string>::iterator it;

    // workaround when parsing .sla that contain register sets
    if(str == "__register_list__")
    {
        return true;
    }

    it = g_allRegisters.find(str);
    if(it == g_allRegisters.end())
    {
        return false;
    }
    return true;
}

// Returns true if the passed in string is an opcode. We determine a string is
// an opcode if it is a hex string beginning with 0x
bool isOpcode(const string& str)
{
    if(str.length() > 2)
    {
        if(str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
        {
            return true;
        }
    }

    return false;

    // regex method was too slow
    // return boost::regex_match(str, g_opcodeRegex);
}

// returns true if the passed in string is an integer
bool isInteger(const string& str)
{
    if(str.length() >= 1)
    {
        if(str[0] >= '0' && str[0] <= '9')
        {
            return true;
        }
    }

    return false;

    // regex method was too slow
    //return boost::regex_match(str, g_integerRegex);
}

// an immediate is a hex string or decimal string
bool isImmediate(const string& str)
{
    // workaround when parsing .sla that contain register sets
    if(str == "__immediate_list__")
    {
        return true;
    }

    if(isOpcode(str) || isInteger(str))
    {
        return true;
    }

    return false;
}

// TODO: comment
static int parseInstructionsWorker(PARSED_DATA& parsedData,
                                   const char* buffer,
                                   unsigned long long start,
                                   unsigned long long end)
{
    // to improve performance each thread has it's own copy of these data 
    // structures that are merged together later
    set<string> registers;
    set<string> mnemonics;
    map<string, Instruction*> allInstructions;
    const char* bufferStart = NULL;

    // loop through the file portion line by line
    bufferStart = buffer + start;
    for(unsigned long long i = start; i <= end; i++)
    {        
        if(buffer[i] == '\n')
        {
            int result = 0;
            unsigned long long len = 0;

            len = &buffer[i] - bufferStart;
            string line(bufferStart, len);

            // parse each line
            result = parseInstructionsParser(parsedData,
                                             0,
                                             line,
                                             registers,
                                             mnemonics,
                                             allInstructions);
            if(result != 0)
            {
                goto ERROR_EXIT;
            }

            bufferStart = &buffer[i];
        }    
    }

    // merge the data back up
    parsedData.mnemonicsMutex.lock();
    parsedData.mnemonics.merge(mnemonics);
    parsedData.mnemonicsMutex.unlock();

    parsedData.registersMutex.lock();
    parsedData.registers.merge(registers);
    parsedData.registersMutex.unlock();

    parsedData.registersMutex.lock();
    parsedData.allInstructions.merge(allInstructions);
    parsedData.registersMutex.unlock();

    incrementWorkerCompletions();
    return 0;

ERROR_EXIT:
    incrementWorkerCompletions();
    incrementWorkerFailures();
    return -1;
}

// returns true if the character should be split
// into it's own element
static bool splitChar(char ch)
{
    switch(ch)
    {
        case ',':
        case '@':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '+':
        case '-':
        case '#':
        case ' ':
        case '*':
        case '!':
        case '\t':
        case '\r':
        case '\n':
            return true;
        default:
            return false;
    }

    return false;
}

// returns true if the character is a whitespace char
static bool isCharWhiteSpace(char ch)
{
    switch(ch)
    {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            return true;
        default:
            return false;
    }

    return false;
}

// splits a line of disassembly into a vector of strings
static int splitDisassemblyLine(vector<string>& lineSplit, const string& line)
{
    string currSplit = "";

    for(unsigned int i = 0; i < line.size(); i++)
    {
        bool shouldSplit = false;
        bool shouldSkip = false;

        shouldSplit = splitChar(line[i]);
        if(shouldSplit == true)
        {
            if(currSplit.size() > 0)
            {
                //cout << "currSplit: " << currSplit << endl;
                lineSplit.emplace_back(currSplit);
                currSplit = "";
            }

            shouldSkip = isCharWhiteSpace(line[i]);
            if(shouldSkip == false)
            {
                // non-ws char, append to our vector
                lineSplit.emplace_back(std::string(1, line[i]));
            }
        }
        else
        {
            currSplit.push_back(line[i]);
        }
    }

    if(currSplit.size() > 0)
    {
        lineSplit.emplace_back(currSplit);
    }

    return 0;
}


// tokenizes the input instructions and appends them to the allInstructions set
static int parseInstructionsParser(PARSED_DATA& parsedData, 
                                   unsigned int lineNum,
                                   string& line,
                                   set<string>& registers,
                                   set<string>& mnemonics,
                                   map<string, Instruction*>& allInstructions)
{
    map<string, Instruction*>::iterator itr;
    vector<string> lineSplit;
    string opcode;
    int result = 0;

    Instruction* currInstruction = new Instruction();
    if(currInstruction == NULL)
    {
        cout << "[-] Error line " << lineNum << ": Failed to allocate!!" << endl;
        goto ERROR_EXIT;        
    }

    // We want to split these fillers from register values
    // TODO: improve performance here
    splitDisassemblyLine(lineSplit, line);
    
    // Our combining algorithm needs to be rewritten to support more than 26 
    // tokens. For the time being bail
    if(lineSplit.size() > MAX_TOKENS)
    {
        cout << "[-] Error line " << lineNum << ": Line has more than MAX_TOKENS!!" << endl;
        cout << line << endl;
        throw 1;
        delete currInstruction;
        goto ERROR_EXIT;
    }

    // tokenize each line component and add it to the Instruction
    for(unsigned int i = 0; i < lineSplit.size(); i++)
    {
        if(i == 0)
        {
            unsigned int opcodeBitLength = 0;

            // the first element on the line must be the opcode
            result = isOpcode(lineSplit[i]);
            if(result != true)
            {
                cout << "[-] Error line " << lineNum << ": First field is not an hex opcode!!" << endl;
                cout << "[-] Got: " << lineSplit[i] << endl;
                delete currInstruction;
                goto ERROR_EXIT;
            }

            currInstruction->setOpcode(lineSplit[i]);

            // we need to keep track of the maximum bit length for the
            // combining stage
            opcodeBitLength = currInstruction->getOpcode().length();
            updateOpcodeSize(opcodeBitLength);

            if(opcodeBitLength > parsedData.maxOpcodeBits)
            {
                parsedData.maxOpcodeBitsMutex.lock();
                if(opcodeBitLength > parsedData.maxOpcodeBits)
                {
                    cout << "  [*] Updating bit length from " << parsedData.maxOpcodeBits << " to " << opcodeBitLength << endl;
                    parsedData.maxOpcodeBits = opcodeBitLength;
                }
                parsedData.maxOpcodeBitsMutex.unlock();
            }
        }
        else
        {
            InstructionComponentType currType;

            // all remaining elements on the line are components of the 
            // instruction
            if(isRegister(lineSplit[i]))
            {
                currType = TYPE_REGISTER;                
                registers.insert(lineSplit[i]);
                
            }
            else if(isImmediate(lineSplit[i]))
            {
                currType = TYPE_IMMEDIATE;
            }
            else
            {            
                mnemonics.insert(lineSplit[i]);
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
        goto ERROR_EXIT;
    }

    opcode = currInstruction->getOpcode();

    // check for duplicate instructions before inserting
    itr = allInstructions.find(opcode);
    if(itr != allInstructions.end())
    {
        cout << "[-] Error line " << lineNum << ": Found duplicate opcode!!" << endl;
        delete currInstruction;
        goto ERROR_EXIT;
    }

    // everything is good, insert instruction into our set    
    allInstructions.insert({{std::move(opcode), currInstruction}});

    return 0;

ERROR_EXIT:    
    return -1;
}

// tokenizes the input instructions and appends them to the allInstructions set
int parseInstructions(PARSED_DATA& parsedData, unsigned int fileId)
{
    boost::timer::auto_cpu_timer t;
    boost::asio::thread_pool threadPool(parsedData.numThreads);
    unsigned int portion = 0;
    unsigned long long fileSize = 0;
    char* fileBuffer = NULL;
    unsigned long long portionSize = 0;
    unsigned long long start = 0;

    // sanity check thread value
    if(parsedData.numThreads == 0)
    {
        cout << "[-] numThreads cannot be 0" << endl;
        return -1;
    }

    resetThreadPool();

    // TODO: review exit error flow
    // TODO: why pass in fileId?

    // open the input file for parsing
    boost::filesystem::path infile{parsedData.inputFilenames[fileId]};
    boost::filesystem::ifstream ifs{infile, std::ios::ate};

    if(!ifs)
    {
        cout << "[-] Failed to open input file!!" << endl;
        return -1;
    }

    // get the file size
    fileSize = ifs.tellg();    
    ifs.seekg(0, std::ios::beg);

    // TODO: this throws
    fileBuffer = new char[fileSize];
    if(!fileBuffer)
    {
        cout << "[-] Failed to allocate buffer!!" << endl;
        return -1;
    }

    ifs.read(fileBuffer, fileSize);
    ifs.close();
    
    //
    // split the disassembly into 1/num threads pieces
    //
    portionSize = fileSize/parsedData.numThreads;
    
    for(unsigned int i = 0; i < parsedData.numThreads; i++)
    {        
        unsigned long long end = 0;

        if(start >= fileSize)
        {
            cout << "Reached end of file " << endl;
            continue;
        }

        if(i == parsedData.numThreads - 1)
        {
            // last thread, always set end to fileSize
            end = fileSize - 1;
        }
        else
        {
            end = start + portionSize;
            for(unsigned long long j = end; j < fileSize; j++)
            {
                if(fileBuffer[j] == '\n')
                {
                    end = j;
                    break;
                }
            }
        }        

        // queue a worker to work on 1/n of the disassembly
        boost::asio::post(threadPool, 
                          boost::bind(parseInstructionsWorker,
                                      boost::ref(parsedData),
                                      fileBuffer,
                                      start,
                                      end));
        start = end + 1;
    }   

    // TODO: improve poll logic
    while(1)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));

        unsigned int completedCount = getWorkerCompletions();
        unsigned int failCount = getWorkerFailures();

        //cout << "Test cases: " << completed_count << "/" << lineNum  << " Fail cases: " << fail_count << endl;
        
        // check if we exceeded our max number of failures
        if(failCount > 0)
        {
            // abort the rest of the threads         
            threadPool.stop();
            break;
        }

        // check if we finished our submitted jobs
        if(completedCount >= portion)
        {
            // finished
            break;
        }
    }

    threadPool.join();

    delete [] fileBuffer;

    if(getWorkerFailures() > 0)
    {
        return -1;
    }

    // Copy the instructions into the combined instructions set. We need to
    // save the original allInstructions to recreate the registers lists when
    // we print out the instructions
    parsedData.combinedInstructions = parsedData.allInstructions;

    // check if we have a variable length opcodes
    parsedData.variableLengthISA = hasVariableLengthOpcodes();
    return 0;
}

// Walks through all instructions that have combined registers and figures out
// the register list and register variable name and appends them to 
// registerVariables. Once registerVariables is filled out attachVariables is 
// filled out
void  computeAttachVariables(PARSED_DATA& parsedData)
{    
    boost::timer::auto_cpu_timer t;
    std::set<Instruction*>::iterator it;

    // iterate through all combined instructions and update registerVariables
    for(auto& x: parsedData.combinedInstructions)
    {
        x.second->computeAttachVariables(parsedData.allInstructions,
                                         parsedData.registerVariables,
                                         parsedData.slas);
    }

    for(auto& y: parsedData.registerVariables)
    {
        // y.second = string consisting all delimited by space
        // y.first = register variable name
        parsedData.attachVariables[y.second].insert(y.first);
    }
    return;
}

// TODO: wrong comment
// Walks through all instructions that have combined registers and figures out
// the register list and register variable name and appends them to 
// registerVariables. Once registerVariables is filled out attachVariables is 
// filled out.
void computeTokenInstructions(PARSED_DATA& parsedData)
{    
    boost::timer::auto_cpu_timer t;
    std::set<Instruction*>::iterator it;

    // iterate through all combined instructions. getOpcodeOutputString() will
    // append new tokens to the tokenInstructions set
    for(auto& x: parsedData.combinedInstructions)
    {
        int index = convertOpcodeSizeToIndex(x.first.length());
        if(index < 0)
        {
            cout << "Invalid opcode size!!" << endl;
            throw 1;
        }

        x.second->getOpcodeOutputString(parsedData.tokenInstructions[index]);
    }

    return;
}

// worker that deletes the instruction from parsedData.allinstructions
int clearParserWorker(PARSED_DATA& parsedData, 
                      unsigned long long start,
                      unsigned long long end)
{
    map<string, Instruction*>::iterator startItr;
    map<string, Instruction*>::iterator endItr;

    startItr = parsedData.allInstructions.begin();

    std::advance(startItr, start);
    endItr = startItr;
    std::advance(endItr, end-start + 1);

    for(; startItr != endItr; startItr++)
    {
        delete startItr->second;
    }

    incrementWorkerCompletions();
    return 0;
}

// splits the instructions to be deleted onto a thread pool
int clearParserScheduler(PARSED_DATA& parsedData)
{
    boost::asio::thread_pool threadPool(parsedData.numThreads);
    unsigned int portion = 0;
    unsigned long long numInstructions = 0;
    unsigned long long portionSize = 0;
    unsigned long long start = 0;

    // sanity check thread value
    if(parsedData.numThreads == 0)
    {
        cout << "[-] numThreads cannot be 0" << endl;
        return -1;
    }

    resetThreadPool();

    //
    // split freeing the instructions into 1/num threads pieces
    //
    numInstructions = parsedData.allInstructions.size();
    if(numInstructions < 1024)
    {
        parsedData.numThreads = 1;
        portionSize = numInstructions;
    }
    else
    {
        portionSize = numInstructions/parsedData.numThreads;
    }
    
    for(unsigned int i = 0; i < parsedData.numThreads; i++)
    {        
        unsigned long long end = 0;

        if(i == parsedData.numThreads - 1)
        {
            // last thread, always set end to fileSize
            end = numInstructions - 1;
        }
        else
        {
            end = start + portionSize;
        }

        // queue a worker to work on 1/n of the disassembly
        boost::asio::post(threadPool, 
                          boost::bind(clearParserWorker,
                                      boost::ref(parsedData),
                                      start,
                                      end));
        start = end + 1;
        portion++;
    }

    // TODO: improve poll logic
    while(1)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        unsigned int completedCount = getWorkerCompletions();

        // check if we finished our submitted jobs
        if(completedCount >= portion)
        {
            // finished
            break;
        }
    }

    threadPool.join();
    return 0;
}

// free the parser data structure
void clearParserData(PARSED_DATA& parsedData, bool save_registers)
{
    boost::timer::auto_cpu_timer t;
    cout << "[*] Freeing parser data" << endl;

    // free any instructions that we allocated during the combine phase
    for(auto& y: parsedData.combinedInstructions)
    {
        if(y.second->getNeedsFree() == true)
        {
            delete y.second;
        }
    }

    // multithreaded free the allInstructions map
    // this is a perf bottleneck, even after multithreading
    if(parsedData.allInstructions.size() > 0)
    {
        clearParserScheduler(parsedData);
        parsedData.allInstructions.clear();
    }

    // no other data structures allocated Instructions    
    parsedData.combinedInstructions.clear();
    parsedData.registerVariables.clear();
    parsedData.attachVariables.clear();

    for(unsigned int i = 0; i < sizeof(parsedData.tokenInstructions)/sizeof(parsedData.tokenInstructions[0]); i++)
    {
        parsedData.tokenInstructions[i].clear();
    }

    if(!save_registers)
    {
        parsedData.registers.clear();
        parsedData.mnemonics.clear();
    }
}
