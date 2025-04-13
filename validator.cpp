//-----------------------------------------------------------------------------
// File: validator.cpp
//
// Handles command line argument parsing invoking the disassembly routine.
//
// Copyright (c) Oberoi Security Solutions. All rights reserved.
// Licensed under the Apache 2.0 License.
//-----------------------------------------------------------------------------

#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem/fstream.hpp>
#include <loadimage.hh>
#include <sleigh.hh>
using namespace std;

// This is a tiny LoadImage class which feeds the executable bytes to the translator
// Taken straight from sleighexample.cc
class MyLoadImage : public LoadImage {
  uintb baseaddr;
  int4 length;
  uint1 *data;
public:
  MyLoadImage(uintb ad,uint1 *ptr,int4 sz) : LoadImage("nofile") { baseaddr = ad; data = ptr; length = sz; }
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
  virtual string getArchType(void) const { return "myload"; }
  virtual void adjustVma(long adjust) { }
};

// This is the only important method for the LoadImage. It returns bytes from the static array
// depending on the address range requested
void MyLoadImage::loadFill(uint1 *ptr,int4 size,const Address &addr)

{
  uintb start = addr.getOffset();
  uintb max = baseaddr + (length-1);
  for(int4 i=0;i<size;++i) {	// For every byte requestes
    uintb curoff = start + i; // Calculate offset of byte
    if ((curoff < baseaddr)||(curoff>max)) {	// If byte does not fall in window
      ptr[i] = 0;		// return 0
      continue;
    }
    uintb diff = curoff - baseaddr;
    ptr[i] = data[(int4)diff];	// Otherwise return data from our window
  }
}

// Here is a simple class for emitting assembly.  In this case, we send the strings straight
// to standard out.
class AssemblyRaw : public AssemblyEmit {
public:
  virtual void dump(const Address &addr,const string &mnem,const string &body) {
        disassembly = mnem + " " + body;
        boost::trim(disassembly);
  }
  string disassembly;
};

// converts unsigned char to two byte hex value
#define CHAR2HEX( x ) setw(2) << setfill('0') << uppercase << hex << (unsigned int)x

int parseInputAndDisassemble(string& inputFilename, string& outputFilename, string& slaFilename);
int convertOpcodeToBinary(string& opcode, vector<unsigned char>& opcodeBytes);
int convertHexNibbletoInteger(unsigned char x);
int sleighDisassemble(string& slaFilename, vector<unsigned char>& opcodeBytes, string& disassembly);

int main(int argc, char *argv[])
{
    boost::program_options::options_description desc{"Ghidra Processor Module Generator Validator"};
    boost::program_options::variables_map args;
    string inputFilename;
    string outputFilename;
    string slaFilename;
    int result = 0;

    cout << "Ghidra Processor Module Generator Validator" << endl;

    //
    // command line arg parsing
    //

    try
    {
        desc.add_options()
            ("input-file,i", boost::program_options::value<string>(&inputFilename), "Path to a newline delimited text file containing all opcodes and instructions for the processor module. Required.")
            ("output-file,o",boost::program_options::value<string>(&outputFilename)->default_value("output.txt"), "Output file. Defaults to output.txt if not specified.")
            ("sla-file,s",boost::program_options::value<string>(&slaFilename), "Path to the compiled processor .sla.")
            ("help,h", "Help screen");

        store(parse_command_line(argc, argv, desc), args);
        notify(args);

        if(args.count("help") || argc == 1)
        {
            cout << desc << endl;
            return 0;
        }

        if(args.count("input-file") == 0)
        {
            cout << "Input file name is required!!" << endl;
            return -1;
        }

        if(args.count("sla-file") == 0)
        {
            cout << "Sla file name is required!!" << endl;
            return -1;
        }
    }
    catch (const boost::program_options::error &ex)
    {
        cout << "[-] Error parsing command line: " << ex.what() << endl;
        return -1;
    }

    cout << "[*] Input file: " << inputFilename << endl;
    cout << "[*] Compiled SLA file: " << slaFilename << endl;
    cout << "[*] Outputting (might take a while) to: " << outputFilename << endl;

    result = parseInputAndDisassemble(inputFilename, outputFilename, slaFilename);
    if(result != 0)
    {
        return result;
    }

    cout << "[*] Successfully created output disassembly file. Diff input and output files to find errors in the SLA." << endl;
    return 0;
}

// Parses the input file for addresses and passes it to the SLEIGH disassembler for output
int parseInputAndDisassemble(string& inputFilename, string& outputFilename, string& slaFilename)
{
    unsigned int lineNum = 0;
    int result = 0;
    std::string line;

    // open the input file for parsing
    boost::filesystem::path infile{inputFilename};
    boost::filesystem::ifstream ifs{infile};

    boost::filesystem::path outfile{outputFilename};
    boost::filesystem::ofstream ofs{outfile};

    if(!ifs)
    {
        cout << "[-] Failed to open input file!!" << endl;
        return -1;
    }

    if(!ofs)
    {
        cout << "[-] Failed to open output file!!" << endl;
        return -1;
    }

    //
    // parse the input file line by line
    //
    while (std::getline(ifs, line))
    {
        vector<string> lineSplit;
        vector<unsigned char> opcodeBytes;
        string disassembly;

        lineNum++;

        // split the line into components
        boost::split(lineSplit, line, boost::algorithm::is_space(), boost::token_compress_on);

        if(lineSplit.size() < 1)
        {
            continue;
        }

        result = convertOpcodeToBinary(lineSplit[0], opcodeBytes);
        if(result != 0)
        {
            cout << "Failed to covert opcode!!" << endl;
            goto exit;
        }

        result = sleighDisassemble(slaFilename, opcodeBytes, disassembly);
        if(result != 0)
        {
            goto exit;
        }

        ofs << "0x";
        for (auto& x: opcodeBytes)
        {
            ofs << CHAR2HEX(x);
        }
        ofs << " " << disassembly;
        ofs << endl;
    }

    result = 0;

exit:
    ifs.close();
    ofs.close();
    return result;
}

// disassembles opcode bytes using the passed in SLA file
int sleighDisassemble(string& slaFilename, vector<unsigned char>& opcodeBytes, string& disassembly)
{
    unsigned char buffer[4096] = {0};

    // initialize instruction to disassemble
    for(unsigned int i = 0; i < opcodeBytes.size(); i++)
    {
        buffer[i] = opcodeBytes[i];
    }

    // instantiate sleigh
    try
    {
        MyLoadImage loader(0, (uint1*)buffer, sizeof(buffer));

        // Set up the context object
        ContextInternal context;

        // Set up the disassembler
        Sleigh trans(&loader, &context);

        // Read sleigh file into DOM
        DocumentStorage docstorage;
        Element *sleighroot = docstorage.openDocument(slaFilename)->getRoot();
        docstorage.registerTag(sleighroot);
        trans.initialize(docstorage); // Initialize the translator

        AssemblyRaw assememit;	// Set up the disassembly dumper
        Address addr(trans.getDefaultCodeSpace(), 0); // First disassembly address

        // dump the disassembly now
        trans.printAssembly(assememit, addr);
        disassembly = assememit.disassembly;
    }
    catch(XmlError e)
    {
        cout << "Failed to instantiate SLEIGH. Is processor SLA invalid?" << endl;
        return -1;
    }
    catch(BadDataError e)
    {
        // disassembly error, just report it as a success so it appears in the output
        disassembly = "Error";
        return 0;
    }
    catch(...)
    {
        cout << "Unknown error during disassembly!!\n";
        return -3;
    }

    return 0;
}

// converts an opcode in the of 0xaabb... or 0b0011... to a an array of raw bytes
int convertOpcodeToBinary(string& opcode, vector<unsigned char>& opcodeBytes)
{
    int opcodeLength = 0;

    // opcode must begin with 0x or 0b
    if(opcode[0] != '0')
    {
        cout << "Opcode must begin with 0x or 0b!!" << endl;
        return -1;
    }

    if(opcode[1] == 'x' || opcode[1] == 'X')
    {
        opcodeLength = opcode.length() - 2;
        if((opcodeLength % 2) != 0)
        {
            cout << "Hex opcode length must be divisble by 2!!" << endl;
            return -2;
        }

         // loop through the hex string, converting each byte
        for(unsigned int i = 2; i < opcode.length(); i += 2)
        {
            unsigned char value;
            unsigned char high;
            unsigned char low;

            // convert the hex string to a byte
            high = convertHexNibbletoInteger(opcode[i]);
            low = convertHexNibbletoInteger(opcode[i+1]);

            value = (high << 4) | low;

            opcodeBytes.push_back(value);
        }

        return 0;
    }
    else if(opcode[1] == 'b' || opcode[1] == 'B')
    {
        opcodeLength = opcode.length() - 2;
        if((opcodeLength % 8) != 0)
        {
            cout << "Binary opcode length must be divisble by 8!!" << endl;
            return -2;
        }

        // loop through the bit string, converting each byte
        for(unsigned int i = 2; i < opcode.length(); i += 8)
        {
            unsigned char value = 0;

            for(unsigned int j = 0; j < 8; j++)
            {
                value = value << 1;
                if(opcode[i + j] == '1')
                {
                    value = value | 1;
                }
            }
            opcodeBytes.push_back(value);
        }

        return 0;
    }
    else
    {
        cout << "Opcode must begin with 0x or 0b!!" << endl;
        return -1;
    }

    return 0;
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
