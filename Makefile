CC=g++
CFLAGS=-c -Wall -O2 -fpic
LDFLAGS=-lpthread -lssl -lcrypto -shared
SOURCES=ClientSocket.cpp  HexDumper.cpp  IPGenerator.cpp  Thread.cpp  TorConnector.cpp  UdpConnector.cpp SmbGen.cpp SSLClient.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=libNetLib.so


all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

.PHONY clean:
	-rm -f $(EXECUTABLE)
	-rm -f $(OBJECTS)

cleanDebug: clean
Debug: all

cleanRelease: clean
Release: all
