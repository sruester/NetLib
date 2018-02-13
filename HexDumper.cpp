/*
 * MIT License
 *
 * Copyright (c) 2018 sruester
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "HexDumper.h"
#include <cstdlib>
#include <stdio.h>
#include <inttypes.h>

void HexDumper::HexPrint(FILE *outchan, string &data, size_t width){
	size_t offset = 0;
	size_t i = 0;

	while(true){

		for(i = 0; (i < width) && (offset + i) < data.length(); i++){
			fprintf(outchan, "%02X ", ((uint8_t)data[offset + i]));
		}

		if(offset + i >= data.length())
			for(;i < width; i++)
				fprintf(outchan, "   ");

		fprintf(outchan, "   ");

		for(i = 0; (i < width) && (offset + i) < data.length(); i++){
			if(data[offset + i] < 32 || data[offset + i] > 126)
				fprintf(outchan, ".");
			else
				fprintf(outchan, "%c", (uint8_t)data[offset + i]);
		}

		fprintf(outchan, "\n");
		offset += width;

		if(offset >= data.length()) break;

	}
}

void HexDumper::Print(string &data, size_t width = 8){
	HexPrint(stdout, data, width);
}

void HexDumper::PrintToCerr(string &data, size_t width = 8){
	HexPrint(stderr, data, width);
}

