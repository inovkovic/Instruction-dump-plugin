#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>

#include "Plugin.h"

struct Configuration {
	char logName[10];
	uint numberOfInstructions;	// how many instructions to read
	uint numberOfJumps;			// how deep is recursion going to be
	bool recordEntrance;		// whether to record steping in CALL instruction
	bool recordRegMod;			// whether to record if registers were modified by user
	bool recordReg;				// whether to record register values
	bool recordStog;			// record stog state
	uint stackSize;				// number of stog records to read in bytes
	bool recordMemory;			// record memory which is referenced in registers
	uint memorySize;			// how much memory to record in bytes
};

struct State {
	std::vector<uint> retAddr;				//	return addresses when CALL is encountered
	bool stepIn;							//	1 - command was STEP_IN 0 - command was STEP_OVER
	std::vector<bool> regMod;				//  any register modified by user
	bool wasCall;							//	last instruction was CALL
	std::vector<char> stackDump;
	std::vector<char> memoryDump;
};

struct MemoryBlock {
	ulong base;
};

HINSTANCE        hinst;                // DLL instance
HWND             hwmain;               // Handle of main OllyDbg window

Configuration config;
State		  state;

std::fstream file;


//	function for dumping instructions
void cdecl recordInstructions(t_disasm *disasm, uint depth);


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

   //	reading configuration file
   file.open("instDump.conf", std::ios::in);
 /*  fscanf(file, "%s %lu %lu %d %d %d", config.logName, &config.numberOfInstructions, &config.numberOfJumps, &config.recordEntrance, &config.recordRegMod, &config.recordReg);
   fclose(file);*/
   file >> config.logName >> config.numberOfInstructions >> config.numberOfJumps >> config.recordEntrance >> config.recordRegMod >> config.recordReg 
	   >> config.recordStog >> config.stackSize >> config.recordMemory >> config.memorySize;
   file.close();

   state.stepIn = false;
   state.wasCall = false;
   state.stackDump.resize(config.stackSize);
   state.memoryDump.resize(config.memorySize * 8);


   // log file
   file.open(config.logName, std::ios::out);

 //  fprintf(file, "%lu %lu %d %d %d\n", config.numberOfInstructions, config.numberOfJumps, config.recordEntrance, config.recordRegMod, config.recordReg);

   Addtolist(0,0,"Instruction dump plugin v 0.1");
   Addtolist(0,-1,"  Copyright (C) 2015 Igor Novkovic");
 
   return 0;
};

extc void _export cdecl ODBG_Plugindestroy(void) {
	file.close();
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
	/*file.close();
	file.open(config.logName, std::ios::in);*/
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


extc int _export cdecl ODBG_Paused(int reason,  t_reg *reg) {
	ulong srcsize;
	t_disasm disasm;
	uchar cmd[MAXCMDSIZE];

	switch(reason) {
		
		case PP_EVENT:
				if(state.wasCall == true) {					// last instruction was call
					if(reg->ip == state.retAddr.back())	{	// current ip == address of instruction after call
						state.stepIn = 0;					// call was steped over
						//state.regMod.push_back(false);
					}
					else {
						state.stepIn = 1;					// call was steped in
						state.regMod.push_back(false);		// add new entry
					}
					state.wasCall = false;					// reset flag

					file << "Entrance: " << state.stepIn << std::endl;
				}
			   

				srcsize = Readcommand(reg->ip, (char*)cmd); 

				if(srcsize != 0) {

					srcsize = Disasm(cmd, srcsize, reg->ip, DEC_UNKNOWN, &disasm, DISASM_ALL, NULL);

					if(disasm.error != 0) 
						break;
					

				//	file << disasm.result << std::endl;

					if(disasm.cmdtype == C_CAL) {							// if instruction is CALL
						state.wasCall = true;
						state.retAddr.push_back(reg->ip + srcsize);			// add new ret address
						recordInstructions(&disasm, 0);						// dump instructions

						file << std::endl;
						file << "Registers: " << std::hex << reg->r[0] << "  " << reg->r[1] << "  " << reg->r[2] << "  " << reg->r[3] << "  " << reg->r[4] << "  " << reg->r[5] << "  "
							<< reg->r[6] << "  " << reg->r[7] << std::endl;		// registers dump

						Readmemory(&(state.stackDump[0]), reg->r[4], config.stackSize, MM_RESILENT);	// stack dump
						file << "Stack: " ;
						for(int i = 0; i < state.stackDump.size(); i++)
							file << std::hex <<(int) state.stackDump[i];
						file << std::endl;

						for(int i = 0; i < 8; i++) {		// is a register containing pointer to a valid memory
							t_memory *mem;

							mem = Findmemory(reg->r[i]);

							if(mem == NULL)
								file << "0 ";
							else
								file << "1 ";
						}
						file << std::endl;

						for(int i = 0; i < 8; i++) {		// for every register containing pointer to a valid memory make dump of that memory
							t_memory *mem;

							mem = Findmemory(reg->r[i]);

							if(mem == NULL)
								file << "0";
							else {
								Readmemory(&(state.memoryDump[i*config.memorySize]), reg->r[i], config.memorySize, MM_RESILENT);
								for(int j = i*config.memorySize; j < i*config.memorySize + config.memorySize; j++)
									file << std::hex << (int)state.memoryDump[j];
								//file << state.memoryDump[i*config.memorySize] << " ";
							}
						}
						file << std::endl;

						t_table *table = (t_table *)  Plugingetvalue(VAL_MEMORY);	// write stack base
						t_memory *mm = (t_memory *) table->data.data;
						file << "Stack base: ";
						for(int i = 0; i < table->data.n; i++) {
							if((mm+i)->type == 0x04000000)
								file << (mm+i)->base << "  ";
						}
						file << std::endl;
					}	
				}
	}

	return 1;
};


void cdecl recordInstructions(t_disasm *disasm, uint depth) {
	ulong ip = disasm->jmpaddr;						
	ulong srcsize;
	uchar cmd[MAXCMDSIZE]; 
	std::string dump;
	t_disasm dis;
	int i, j;

	for(i = 0; i < config.numberOfInstructions; i++) {
		srcsize = Readcommand(ip,(char*)cmd);

		if(srcsize != 0) {
			srcsize = Disasm(cmd, srcsize, ip, DEC_UNKNOWN, &dis, DISASM_ALL, NULL);

			if(dis.error != 0)
				break;

			dump += dis.dump;

			dump.erase(std::remove(dump.begin(), dump.end(), ' '), dump.end());

			if(depth < config.numberOfJumps) {
				if(dis.cmdtype == C_CAL) {							// if instruction is CALL
					file << dump;
					file.clear();
					recordInstructions(&dis, depth + 1);			// dump instructions
				}
			}

			ip += srcsize;
		}
		else
			break;
	}

	//fprintf(file, "%s", dump.c_str());
	file << dump;
};