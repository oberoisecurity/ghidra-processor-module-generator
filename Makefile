CXX=g++
CXXFLAGS=-pipe -O2 -Wall -I $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp/
DEPS = instruction.h output.h parser.h registers.h validator.h
OBJ = main.o instruction.o output.o parser.o
LIBS=-lboost_system -lboost_filesystem -lboost_regex -lboost_program_options
VALIDATOR-DEPS = loadimage.hh sleigh.hh
VALIDATOR-OBJ = validator.o
VALIDATOR-LIBS= -lboost_system -lboost_filesystem -lboost_program_options -L . $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp/libsla.a


all: gpmg gpmg-validator

validator.o: validator.cpp $(VALIDATOR_DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(VALIDATOR-LIBS)


%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(LIBS)

gpmg: $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LIBS)

gpmg-validator: $(VALIDATOR-OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(VALIDATOR-LIBS)

.PHONY: clean
clean:
	rm -f *.o gpmg gpmg-validator
