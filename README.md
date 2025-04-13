# Generator

Ghidra Processor Module Generator (Generator) is a step towards automating the creation of [Ghidra](https://github.com/NationalSecurityAgency/ghidra) processor modules. Generator takes as input one or more text files containing all disassembled instructions for a given instruction set architecture (ISA) and outputs a processor module directory that can be loaded into Ghidra. Specifically Generator:

* combines duplicate instructions
* combines instructions which differ by an immediate value
* combines instructions which differ by a register
* creates a valid processor module directory that includes:
  * Module.manifest
  * .slaspec
  * .cspec
  * .ldefs
  * .pspec

The outputted processor module will be able to disassemble for your given architecture. As all instructions will have an empty p-code definition, Ghidra's decompiler will obviously not work. Generator only supports 1-4 byte ISAs. Both fixed length and variable length ISAs are supported.

## Performance
Generator's runtime is varies based on the size/number of instructions of the input ISA. Generator is multithreaded and by default will use all available cores.

|ISA Size|Time|Ram Usage|Notes|
|---|---:|---:|---|
|1 Byte|<1 sec|<1 GB||
|2 Byte|<2 sec|<1 GB||
|3 Byte|~60 sec|~40 GB||
|4 Byte|~4-5 hours|~40 GB|Requires 4-byte ISA instructions|

Numbers are from an AMD Ryzen 9 7950X3D 16-Core Processor, 128 GB RAM, with NVMe SSD.

## Usage
### Overview
The high-level steps for running Generator on 1-3 byte ISAs are to:

1) Create a newline delimited text file that contains a list of all valid hex opcode and instructions
2) Run Generator on the text file
3) Copy the created processor module directory to your Ghidra/Processors directory
4) Launch Ghidra. Your processor will show up in the list of supported processors

See "Usage (1-3 Byte ISAs)" for detailed instructions. 4 byte ISAs require additional steps. See "Usage (4 Byte ISAs)". 

### Generator Command-Line Arguments
|Command||
|---|---|
|-i [ --input-disassembly ] arg|Path to a newline delimited text file containing all opcodes and instructions for the processor module|
|--input-disassembly-dir arg|Path to a directory with multiple newline delimited text files containing all opcodes and instructions for the processor module|
|-s [ --input-sleigh ] arg|Path to a XML .sla file containing all opcodes and instructions for the processor module|
|--input-sleigh-dir arg|Path to a directory with multiple XML .sla files containing all opcodes and instructions for the processor module|
|-t [ --num-threads ] arg|Number of worker threads to use. Optional. Defaults to number of physical CPUs if not specified|
|-n [ --processor-name ] arg|Name of the target processor. Defaults to "MyProc" if not specified|
|-f [ --processor-family ] arg|Name of the target processor's family. Defaults to "MyProcFamily" if not specified|
|-e [ --endian ] arg|Endianness of the processor. Must be either "little" or "big". Defaults to big if not specified|
|-a [ --alignment ] arg|Instruction alignment of the processor. Defaults to 1 if not specified|
|-b [ --bitness ] arg|Bitness of the processor. Defaults to 32 if not specified|
|--print-registers-only|Only print parsed registers. Useful for debugging purposes. False by default|
|--omit-opcodes|Don't print opcodes in the outputted.sla file. False by default|
|--omit-example-instructions|Don't print example combined instructions in the outputted .sla file. False by default|
|--skip-instruction-combining|Don't combine instructions. Useful for debugging purposes. False by default|
|--additional-registers arg|List of additional registers. Use this option if --print-registers-only is missing registers for your instruction set|
|-h [ --help ]|Help screen|

### Usage (1-3 Byte ISAs)
1) Create a newline delimited text file that contains a list of all valid hex opcodes + instructions. Example (SuperH SH-2):  
> 0x0002 stc sr,r0  
> 0x0003 bsrf r0  
> 0x0004 mov.b r0,@(r0,r0)  
> 0x0005 mov.w r0,@(r0,r0)  
> 0x0006 mov.l r0,@(r0,r0)  
> ...  
> ...  
> 0xEFFE mov #-0x2,r15  
> 0xEFFF mov #-0x1,r15  

Exclude any invalid instructions. The opcode must begin with 0x and must be byte aligned.  
2) Run Generator with `generator --input-disassembly examples/sh-2.txt --print-registers-only` flag. This flag parses all the instructions and will print out only the registers. Verify the output is correct before proceeding.

Ex:  

> ./generator --input-disassembly examples/sh-2.txt --print-registers-only  
> Ghidra Processor Module Generator  
> [\*] Using 16 worker thread(s)  
> [\*] Initializing default Ghidra registers  
> [\*] Parsing instructions examples/sh2.txt  
> [\*] Updating bit length from 0 to 16  
> [\*] Parsed 53752 instructions  
> [\*] Found registers: gbr mach macl pc pr r0 r1 r10 r11 r12 r13 r14 r15 r2 r3 r4 r5 r6 r7 r8 r9 sr vbr  
> [\*] Found mnemonics: # ( ) + , - @ add addc addv and and.b bf bf/s bra braf bsr bsrf bt bt/s clrmac clrt cmp/eq cmp/ge cmp/gt cmp/hi cmp/hs cmp/pl cmp/pz cmp/str div0s div0u div1 dmuls.l dmulu.l dt exts.b exts.w extu.b extu.w jmp jsr ldc ldc.l lds lds.l mac.l mac.w mov mov.b mov.l mov.w mova movt mul.l muls.w mulu.w neg negc nop not or or.b rotcl rotcr rotl rotr rte rts sett shal shar shll shll16 shll2 shll8 shlr shlr16 shlr2 shlr8 sleep stc stc.l sts sts.l sub subc subv swap.b swap.w tas.b trapa tst tst.b xor xor.b xtrct  
> If there are any issues edit registers.h before proceeding.  

3) Manually verify that the registers and mnemonics lists are correct. You can use the `--additional-registers` command line option to add missing registers. On some architectures you may need to remove registers from registers.h and re-compile. **If the registers/mnemonics are incorrect Generator will not work**.
4) Now you are ready to run Generator: `./generator --input-file instructions.txt --processor-name MyProcessor --processor-family ProcessorFamily --endian big --alignment 2`. If all goes well Generator should create a "MyProcessor" directory with all of the required files.
5) Verify that the created processor module directory is valid and compiles with Ghidra's SLEIGH compiler. The SLEIGH compiler script can be found in `ghidra/support/`. Run `sleigh -a <path_to_MyProcessorFamily_dir>`. There should be warnings about unimplemented p-code instructions but otherwise there should be no issues. If the compilation step fails, please submit an issue and upload your instructions.txt file and I will take a look at it.  

Ex:  
> <path_to_ghidra>/ghidra/support/sleigh -a MyProcFamily/  
> Compiling MyProcFamily/data/languages/MyProc.slaspec:  
> WARN  187 NOP constructors found (SleighCompile)  
> WARN  Use -n switch to list each individually (SleighCompile)  
>  
> 1 languages successfully compiled  

6) Now that you've compiled your processor module, you can run `generator-validator` to disassemble your input file and diff the results. This will help you find which instructions require modifications. Run with: `./generator-validator --input-file examples/sh2.txt --sla-file MyProcFamily/data/languages/MyProc.sla --output-file output.txt`. Diff the input file and the output file to find issues. If you find issues, manually correct the .slaspec and recompile with Ghidra's sleigh compiler.  
7) If the processor successfully compiled you should be able to copy your MyProcessor directory to `<path_to_ghidra>/Ghidra/Processors/` directory. When you restart Ghidra your new processor should be listed. Make sure you open your binary as "raw" and manually select your processor module.  

### Usage (4 Byte ISAs)
A 4-byte ISA is too large for Generator to store in memory. To work around this, we split the the input disassembly file into multiple input files and run Generator multiple. The steps involved look this:

1) Create 256 newline delimited text files that contain a list of all valid hex opcode and instructions. Each file should be 1/256th of the total instruction set or approximately 16 million lines each. 
2) Run Generator on the 256 input text files, creating 256 .slaspec files
3) Use Ghidra's SLEIGH compiler to compile the 256 .slaspec files into 256 .sla files
4) Re-run Generator, but with the 256 .sla files as input to combine them into a single .slaspec file
5) Copy the created processor module directory to your Ghidra/Processors directory
6) Launch Ghidra. Your processor will show up in the list of supported processors

1) Create 256 newline delimited texts that each contain 1/256th of the ISA. As before exclude any invalid instructions. Again the opcode must begin with 0x and must be byte aligned.  
2) Run Generator with `generator --input-disassembly-dir examples/split --print-registers-only` flag. This will parse all the text files in the "examples/split" directory the instructions and will print out only the registers. Verify the output is correct before proceeding. Depending on how many files are present and the size of each file this can take a significant amount of time. In the examples/split directory there are two SH-2 files that will be combined.  

Ex:  

> ./generator --input-disassembly-dir examples/split --print-registers-only  
> Ghidra Processor Module Generator  
> [\*] Using 16 worker thread(s)  
> [\*] Initializing default Ghidra registers  
> [\*] Parsing instructions examples/split/sh2_1.txt  
>   [\*] Updating bit length from 0 to 16  
> [\*] Parsed 26872 instructions  
> [\*] Freeing parser data  
> [\*] Parsing instructions examples/split/sh2_2.txt  
> [\*] Parsed 26880 instructions  
> [\*] Freeing parser data  
> [\*] Found registers: gbr mach macl pc pr r0 r1 r10 r11 r12 r13 r14 r15 r2 r3 r4 r5 r6 r7 r8 r9 sr vbr  
> [\*] Found mnemonics: # ( ) + , - @ add addc addv and and.b bf bf/s bra braf bsr bsrf bt bt/s clrmac clrt cmp/eq cmp/ge cmp/gt cmp/hi cmp/hs cmp/pl cmp/pz cmp/str  div0s div0u div1 dmuls.l dmulu.l dt exts.b exts.w extu.b extu.w jmp jsr ldc ldc.l lds lds.l mac.l mac.w mov mov.b mov.l mov.w mova movt mul.l muls.w mulu.w neg > negc nop not or or.b rotcl rotcr rotl rotr rte rts sett shal shar shll shll16 shll2 shll8 shlr shlr16 shlr2 shlr8 sleep stc stc.l sts sts.l sub subc subv swap.b > swap.w tas.b trapa tst tst.b xor xor.b xtrct  
> If there are any issues edit registers.h before proceeding.  
> [\*] Freeing parser data  

3) Manually verify that the registers and mnemonics lists are correct. You can use the `--additional-registers` command line option to add missing registers. On some architectures you may need to remove registers from registers.h and re-compile. **If the registers/mnemonics are incorrect Generator will not work**.
4) Now you are ready to run Generator: `./generator --input-disassembly-dir examples/split --processor-name MyProc --processor-family MyProcFamily --endian big --alignment 2`. If all goes well Generator should create a "MyProcFamily" directory with a .slaspec file for each of the input disassembly text files.
5) Verify that the created processor module directory is valid and compiles with Ghidra's SLEIGH compiler. The SLEIGH compiler script can be found in `ghidra/support/`. Run `sleigh -a -y <path_to_MyProcessorFamily_dir>`. **You must use the -y flag as it forces the SLEIGH compiler to output in the legacy XML format. This is required for the next step.** There should be warnings about unimplemented p-code instructions but otherwise there should be no issues. If the compilation step fails, please submit an issue and upload your instructions.txt file and I will take a look at it. When using examples/split it should successfully compile two languages, one for each input file.  

Ex:  
> <path_to_ghidra>/ghidra/support/sleigh -a MyProcFamily/  
> Compiling MyProcFamily/data/languages/MyProc.slaspec:  
> WARN  104 NOP constructors found (SleighCompile)  
> WARN  Use -n switch to list each individually (SleighCompile)  
>
> WARN  30 NOP constructors found (SleighCompile)  
> WARN  Use -n switch to list each individually (SleighCompile)  
>  
> 2 languages successfully compiled__

6) Step 5 should create one .sla file for each input language. Copy those files .sla (not.slaspec) files into a seperate directory
7) Re-run Generator, but supplying the .sla directory as input: `./generator --input-sleigh-dir intermediate --processor-name SH2 --processor-family SuperH --endian big --alignment 2`. If all goes well Generator will parse and combine all of the .sla files into a single "SuperH" directory with all of the required files.
8) Verify that the created processor module directory is valid and compiles with Ghidra's SLEIGH compiler. The SLEIGH compiler script can be found in `ghidra/support/`. Run `sleigh -a <path_to_MyProcessorFamily_dir>`. There should be warnings about unimplemented p-code instructions but otherwise there should be no issues. If the compilation step fails, please submit an issue and upload your instructions.txt file and I will take a look at it.  
9) Now that you've compiled your processor module, you can run `generator-validator` to disassemble your input file and diff the results. This will help you find which instructions require modifications. Run with: `./generator-validator --input-file examples/sh2.txt --sla-file MyProcFamily/data/languages/MyProc.sla --output-file output.txt`. Diff the input file and the output file to find issues. If you find issues, manually correct the .slaspec and recompile with Ghidra's sleigh compiler.  
10) If the processor successfully compiled you should be able to copy your MyProcessor directory to `<path_to_ghidra>/Ghidra/Processors/` directory. When you restart Ghidra your new processor should be listed. Make sure you open your binary as "raw" and manually select your processor module.  

### Troubleshooting
The most important step in troubleshooting is verifying that the output of --print-registers-only is correct. The registers list must only registers and no mnemonics or instruction components. The mnemonics list must not contain any registers. To remedy this you can manually add\remove registers from regsiter.h or use the --additional-registers command line option to add missing registers. 

There are also register names that are also mnemonics. For example: "b" can be the “b” register or a “branch“ instruction, "lsr" can be “line shift register” or “logical shift right“ instrution. It's important that Generator be told what's a register if it can't figure it out on it's own. 

While most instructions will parse with Generator, there are certain types of instructions that won't merge properly. For example in ARM:

> 0x9eb4 push {r1, r2, r3, r4, r7}  
> 0x9fb4 push {r0, r1, r2, r3, r4, r7}  
> 0xa0b4 push {r5, r7}  

There is a variable list of registers depending on the instruction. Unfortunately this breaks Generator's merging algorithm and must be implemented by hand. I would recommend dropping such instructions from the input disassembly. 

## Manual Next Steps (See Existing Processors for Examples):
Now that you have verified Ghidra can load your processor module you can begin implementing p-code and other changes to get the decompiler to work.

1) Edit the .pspec, .cspec, .ldef files.  
2) Edit the .slaspec file. Rename registers to make more sense. If an instruction uses an immediate and modifies it before displaying you will have to edit the instruction.  
3) Implement p-code for all of the instructions in the .slaspec file to get decompiler support.  

## Issues
* Not all instruction sets are compatible
* Display fields for immediates aren't handled. generator-validator will help show you these. 
* Doesn't work with PC relative addressing. Will require manual fix-ups. generator-validator will help show you these. 
* Won't work on instruction sets where bitfields are not contigious. Example if bits 0-2 and 4-6 are combined to compute an immediate value.
* Not tested with floating point

Please attach your input file when creating an issue.

## Future Work
* Add support for specifying bit patterns as input

## Build
`make generator`  
`make generator-validator GHIDRA_TRUNK=<path_to_Ghidra_trunk>` (requires Ghidra's decompiler headers and libsla.a. GHIDRA_TRUNK points to a clone of Ghidra from trunk, not a release build of Ghidra)

### Build Dependencies
libboost >= 1.76 is required  
libboost-dev  
libboost-filesystem-dev  
libboost-program-options-dev  
libboost-regex-dev  
libboost-system-dev  
libboost-thread-dev  
libboost-timer-dev  
libsla.a (only needed for generator-validator)

#### Building libsla.a
If you want to use generator-validator to validate your processor module against your input file, you will need to build Ghidra's libsla.
1) Checkout Ghidra from trunk. A release build of Ghidra is not sufficient. `git clone https://github.com/NationalSecurityAgency/ghidra` This path will be your GHIDRA_TRUNK directory. 
2) CD to the decompiler source directory: `cd ~/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
3) Compile: `make libsla.a`

## License
Licensed under the Apache 2.0 license. See LICENSE.
