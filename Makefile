CXX=g++
CXXFLAGS=-O3 -pipe -march=native -flto=auto -Wall -Wextra -Wunused -Wunused-but-set-parameter -Wunused-but-set-variable -Wunused-function -I $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp/
DEPS = bitspan.h combine.h instruction.h output.h parser.h parser_sla.h registers.h thread_pool.h validator.h
OBJ = main.o bitspan.o combine.o instruction.o output.o parser.o parser_sla.o thread_pool.o slautil/slautil.o slautil/slaxml.o
LIBS=-lboost_system -lboost_filesystem -lboost_regex -lboost_program_options -lboost_thread -lboost_timer
VALIDATOR-DEPS = loadimage.hh sleigh.hh
VALIDATOR-OBJ = validator.o
VALIDATOR-LIBS= -lboost_system -lboost_filesystem -lboost_program_options -L . $(GHIDRA_TRUNK)/Ghidra/Features/Decompiler/src/decompile/cpp/libsla.a


all: generator generator-validator

validator.o: validator.cpp $(VALIDATOR_DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(VALIDATOR-LIBS)


%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(LIBS)

generator: $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LIBS)

generator-validator: $(VALIDATOR-OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(VALIDATOR-LIBS)

.PHONY: clean
clean:
	rm -f *.o slautil/*.o generator generator-validator
