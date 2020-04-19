# Ghidra Processor Module Generator (GPMG)

*This is alpha software, expect bugs. Please attach your input file when submitting issues.*

Ghidra Processor Module Generator (GPMG) is a step towards automating the creation of [Ghidra](https://github.com/NationalSecurityAgency/ghidra) processor modules. GPMG takes as input a text file containing all disassembled instructions for a given instruction set and outputs a processor module directory that can be loaded into Ghidra. Specifically GPMG:

* combines duplicate instructions
* combines instructions which differ by an immediate value
* combines instructions which differ by a register
* creates a valid processor module directory that includes:
  * Module.manifest
  * .slaspec
  * .cspec
  * .ldefs
  * .pspec

The outputted processor module will be able to disassemble for your given architecture. As all instructions will have an empty p-code definition, Ghidra's decompiler will obviously not work. Realistically GPMG in its current form will only work for 1-3 byte instruction sets. Anything more will likely take up too much RAM.  

## Usage
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
2) Run GPMG with `gpmg --input-file examples/sh-2.txt --print-registers-only` flag. This flag parses all the instructions and will print out only the registers. Verify the output is correct before proceeding.  

Ex:  

> ./gpmg --input-file examples/sh-2.txt --print-registers-only  
> Ghidra Processor Module Generator (GPMG)  
> [\*] Initializing default Ghidra registers  
> [\*] Parsing instructions  
> [\*] Parsed 53752 instructions  
> [\*] Found registers: gbr mach macl pc pr r0 r1 r10 r11 r12 r13 r14 r15 r2 r3 r4 r5 r6 r7 r8 r9 sr vbr  
> If there are any issues edit registers.h before proceeding.  

3) If the registers list is incorrect, use the `--additional-registers` command line option to add registers. Or you can manually edit registers.h and re-compile. If the registers are incorrect GPMG will not work.  
4) Now you are ready to run GPMG: `./gpmg --input-file instructions.txt --processor-name MyProcessor --processor-family ProcessorFamily --endian big --alignment 2`. If all goes well GPMG should create a "MyProcessor" directory with all of the required files.  
5) Verify that the created processor module directory is valid and compiles with Ghidra's SLEIGH compiler. The SLEIGH compiler script can be found in `ghidra/support/`. Run `sleigh -a <path_to_MyProcessorFamily_dir>`. There should be warnings about unimplemented p-code instructions but otherwise there should be no issues. If the compilation step fails, please submit an issue and upload your instructions.txt file and I will take a look at it.  

Ex:  
> <path_to_ghidra>/ghidra/support/sleigh -a MyProcFamily/  
> Compiling MyProcFamily/data/languages/MyProc.slaspec:  
> WARN  187 NOP constructors found (SleighCompile)  
> WARN  Use -n switch to list each individually (SleighCompile)  
>  
> 1 languages successfully compiled  

6) Now that you've compiled your processor module, you can run `gpmg-validator` to disassemble your input file and diff the results. This will help you find which instructions require modifications. Run with: `./gpmg-validator --input-file examples/sh2.txt --sla-file MyProcFamily/data/languages/MyProc.sla --output-file output.txt`. Diff the input file and the output file to find issues. If you find issues, manually correct the .slaspec and recompile with Ghidra's sleigh compiler.  
7) If the processor successfully compiled you should be able to copy your MyProcessor directory to `<path_to_ghidra>/Ghidra/Processors/` directory. When you restart Ghidra your new processor should be listed. Make sure you open your binary as "raw" and manually select your processor module.  

## Manual Next Steps (See Existing Processors for Examples):
Now that you have verified Ghidra can load your processor module you can begin implementing p-code and other changes to get the decompiler to work.

1) Edit the .pspec, .cspec, .ldef files.  
2) Edit the .slaspec file. Rename registers to make more sense. If an instruction uses an immediate and modifies it before displaying you will have to edit the instruction.  
3) Implement p-code for all of the instructions in the .slaspec file to get decompiler support.  

## Issues
* Will choke on instruction sets that are more than 3 bytes long
* Display fields for immediates aren't handled. gpmg-validator will help show you these. 
* Doesn't work with PC relative addressing. Will require manual fix-ups. gpmg-validator will help show you these. 
* Won't work on instruction sets where bitfields are not contigious. Example if bits 0-2 and 4-6 are combined to compute an immediate value.
* Not tested with floating point

Please attach your input file when creating an issue.

## Future Work
* Get 4-byte instruction sets to work. Will require rethinking core algorithms
* Add support for specifying bit patterns as input

## Build
`make gpmg`  
`make gpmg-validator GHIDRA_TRUNK=<path_to_Ghidra_trunk>` (requires Ghidra's decopmiler headers and libsla.a. GHIDRA_TRUNK points to a clone of Ghidra from trunk, not a release build of Ghidra)

### Build Dependencies
libboost-dev  
libboost-filesystem-dev  
libboost-program-options-dev  
libboost-regex-dev  
libboost-system-dev  
libsla.a (only needed for gpmg-validator)

#### Building libsla.a
If you want to use gpmg-validator to validate your processor module against your input file, you will need to build Ghidra's libsla.
1) Checkout Ghidra from trunk. A release build of Ghidra is not sufficient. `git clone https://github.com/NationalSecurityAgency/ghidra` This path will be your GHIDRA_TRUNK directory. 
2) CD to the decompiler source directory: `cd ~/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`
3) Compile: `make libsla.a`

## License
Licensed under the Apache 2.0 license. See LICENSE.
