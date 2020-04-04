CXX=g++
CXXFLAGS=-pipe -O2 -Wall
DEPS = instruction.h output.h parser.h registers.h
OBJ = main.o instruction.o output.o parser.o
LIBS=-lboost_system -lboost_filesystem -lboost_regex -lboost_program_options

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(LIBS)

gpmg: $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LIBS)

.PHONY: clean
clean:
	rm -f *.o gpmg
