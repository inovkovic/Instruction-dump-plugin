#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "Plugin.h"

HINSTANCE        hinst;                // DLL instance
HWND             hwmain;               // Handle of main OllyDbg window

FILE *file;

uchar *output;		// string of instructions which are going to be written in a file
uint outputPos;		// last position in output string
uint outputSize;

//	configuration variables, read at the startup
uint numberOfInstructions;	// how many instructions to read
uint numberOfJumps;			// how deep is recursion going to be

uint nextInstructionAddress; // address of instruction after call/jxx instruction

//	function for dumping instructions
void cdecl recordInstructions(t_disasm *disasm, uint depth);

void writeOutput();


BOOL WINAPI DllEntryPoint(HINSTANCE hi,DWORD reason,LPVOID reserved) {
  if (reason==DLL_PROCESS_ATTACH)
    hinst=hi;                          // Mark plugin instance
  return 1;                            // Report success
};


extc int _export cdecl ODBG_Plugindata(char shortname[32]) {
  strcpy(shortname,"Instruction dump plugin");      
  return PLUGIN_VERSION;
};

extc int _export cdecl ODBG_Plugininit(int ollydbgversion,HWND hw,ulong *features) {

   if (ollydbgversion<PLUGIN_VERSION)
     return -1;

   hwmain=hw;


   nextInstructionAddress = 0;  //	setting flag down


   //	reading configuration file
   file = fopen("instDump.conf", "r");
   fscanf(file, "%lu %lu", &numberOfInstructions, &numberOfJumps);
   fclose(file);

   outputSize = numberOfInstructions * numberOfJumps * 2;
   
   output = (uchar*) malloc(outputSize);

   outputPos = 0;

  //	dump file
   file = fopen("instructionDump.txt", "w");

   Addtolist(0,0,"Instruction dump plugin v 0.1");
   Addtolist(0,-1,"  Copyright (C) 2015 Igor Novkovic");
 
   return 0;
};

extc void _export cdecl ODBG_Plugindestroy(void) {
	fclose(file);
	free(output);
};

extc int _export cdecl ODBG_Pluginmenu(int origin,char data[4096],void *item) {
  switch (origin) {
    case PM_MAIN:                      
      strcpy(data,"0 &About");
      return 1;

  };
  return 0;                           
};

extc void cdecl ODBG_Pluginreset(void) {
	fclose(file);
	file = fopen("instructionDump.txt", "w");
	outputPos = 0;
}


extc void _export cdecl ODBG_Pluginaction(int origin,int action,void *item) {
  if (origin==PM_MAIN) {
    switch (action) {
      case 0:
        MessageBoxA(hwmain,"Instruction dump plugin v 0.1\nCopyright (C) 2015 Igor Novkovic", "Instruction dump plugin",MB_OK|MB_ICONINFORMATION);
        break;
    }; 
  }
};


extc int _export cdecl ODBG_Paused(int reason, t_reg *reg) {
	ulong srcsize;
	t_disasm disasm;
	uchar cmd[MAXCMDSIZE];

	switch(reason) {
	case PP_EVENT:
		if(nextInstructionAddress != 0) {		//	if previous instruction was CALL/JXX
			if(reg->ip == nextInstructionAddress) // if current instruction is instruction after CALL/JXX instruction
				fprintf(file, "\n0\n");			// command was step over
			else								// if current instruction is one pointed to by CALL/JXX
				fprintf(file, "\n1\n");			// command was step into

			nextInstructionAddress = 0;			// reset flag
		}

		srcsize = Readcommand(reg->ip, (char*)cmd); 

		if(srcsize != 0) {

			srcsize = Disasm(cmd, srcsize, reg->ip, DEC_UNKNOWN, &disasm, DISASM_ALL, NULL);

			if(disasm.error != 0)
				break;

			if(/*disasm.cmdtype == C_JMC || */disasm.cmdtype == C_CAL) {  // if instruction is CALL/JXX
				nextInstructionAddress = reg->ip + srcsize;			// set flag
				recordInstructions(&disasm, 0);						// dump instructions
			}

			if(outputPos != 0)
				writeOutput();

			return 1;
		}
	}
	return 0;
};

void writeOutput() {
	output[outputPos] = '\0';
	fprintf(file, "%s", output);
	outputPos = 0;
}

void cdecl recordInstructions(t_disasm *disasm, uint depth) {	//  Readcommand -> readmemory ?
	ulong ip = disasm->jmpaddr;						
	ulong srcsize;
	uchar cmd[MAXCMDSIZE]; 
	t_disasm dis;
	int i, j;

	for(i = 0; i < numberOfInstructions; i++) {
		srcsize = Readcommand(ip,(char*)cmd);

		if(srcsize != 0) {
			srcsize = Disasm(cmd, srcsize, ip, DEC_UNKNOWN, &dis, DISASM_ALL, NULL);

			if(dis.error != 0)
				break;

			//fprintf(file, "%s", dis.dump);

			for(j = 0; dis.dump[j] != '\0'; j++) {
				if(dis.dump[j] == ' ')
					continue;
				output[outputPos] = dis.dump[j];
				outputPos++;
				if(outputPos == (outputSize -1))
					writeOutput();
			}

			if(depth < numberOfJumps) {
				if(/*dis.cmdtype == C_JMC || */dis.cmdtype == C_CAL)	// if instruction is CALL/JXX
					recordInstructions(&dis, depth + 1);			// dump instructions
			}

			ip += srcsize;
		}
		else
			break;
	}
};