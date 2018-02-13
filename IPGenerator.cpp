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
#include "IPGenerator.h"
#include <cstdlib>
#include <time.h>

using namespace std;

int IPGenerator::seedoffset = 1;

IPGenerator::IPGenerator(void){
	srandom((unsigned int)time(0) + seedoffset++);
}

uint8_t IPGenerator::rnd(uint16_t modulo){
	static unsigned int offset = 1234;
	srand((unsigned)time(0) + ++offset);
	return random() % modulo;
}

bool IPGenerator::checkip(uint8_t *ip){
	if(ip[0] >= 224) return false;
	if(ip[0] == 0)   return false;
	if(ip[0] == 255) return false;
	if(ip[0] == 127) return false;
	if(ip[0] == 10)  return false;
	if(ip[3] == 0)   return false;
	if(ip[3] == 255) return false;
	if(ip[0] == 169 && ip[1] == 254) return false;
	if(ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) return false;
	if(ip[0] == 191 && ip[1] == 255) return false;
	if(ip[0] == 192 && ip[1] == 168) return false;
	if(ip[0] == 192 && ip[1] == 0 && ip[2] == 0) return false;
	if(ip[0] == 192 && ip[1] == 0 && ip[2] == 2) return false;
	if(ip[0] == 192 && ip[1] == 88 && ip[2] == 99) return false;
	if(ip[0] == 223 && ip[1] == 255 && ip[2] == 255) return false;
	return true;
}

void IPGenerator::GetRandomIP(string &ip){
	uint32_t adr;
	uint8_t *ia = (uint8_t *)&adr;
	char buff[16];

	retry:
	adr = (rnd() << 24);
	adr |= (rnd() << 16);
	adr |= (rnd() << 8);
	adr |= (rnd());
	ia[0] %= 224;
	if(!checkip(ia))
		goto retry;

	snprintf(buff, 16, "%i.%i.%i.%i", ia[0], ia[1], ia[2], ia[3]);
	ip = buff;
}
