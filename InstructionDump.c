#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <functional>

#include "Plugin.h"

struct Configuration {
	char logName[10];
	uint numberOfInstructions;	// how many instructions to read
	uint numberOfJumps;			// how deep is recursion going to be
	uint stackSize;				// number of stog records to read in bytes
	uint memorySize;			// how much memory to record in bytes
};

struct State {
	std::vector<uint> retAddr;				//	return addresses when CALL is encountered
	bool wasCall;							//	last instruction was CALL
	std::time_t timev;
	size_t blockMark;
	uint totalBlocks;
	uint completedBlocks;
	uint signedBlocks;
	size_t lastSignature;
	std::vector<bool> completeBlocks;
	std::vector<bool> signBlocks;
};

struct Module {
	std::string name;
	ulong base;
	ulong size;
	ulong codeBase;
	ulong codeSize;
	ulong dataBase;
};

struct Block {
	ulong startAddress;
	size_t blockMark;
	ulong reg[8];	 // registers before following CALL/JXX
	ulong flags;	 // flag register before following CALL/JXX
	ulong stackBase;
	ulong retAddr;
	ulong probableEndAdd;
	bool wasCalled;
	bool exception;
	std::string stackDump;
	std::string calledInstructionsDump;
	std::string instructionDump;
	std::string instructionDumpAfter;
	bool pointers[8];
	std::string memoryDump;
	std::vector<Module> modules;
	std::vector<Module> after;
	size_t blockSignature;
};

// ako se nastavlja debugankja iz datoteke procitati lastblocksignature ako ne postoji entry staviti trenutni blokc kao prvi

HINSTANCE        hinst;                // DLL instance
HWND             hwmain;               // Handle of main OllyDbg window

Configuration config;
State		  state;

std::fstream file;

std::vector<Block> blocks;


void cdecl instructionDump(ulong add, uint depth, std::string &buffer);

void cdecl registerDump(t_reg *reg, ulong *r);

void cdecl stackDump(t_reg *reg, std::string &dump);

void cdecl checkRegValues(ulong *reg, bool *pointers);

void cdecl memoryDump(Block &block, std::string &dump);

void cdecl stackBaseDump(t_reg *reg, ulong &stackBase);

void cdecl modulesDump(std::vector<Module> &modules);

size_t cdecl hashInt(int i);

size_t cdecl hashIntArray(int *i, int size);

size_t cdecl hashString(std::string& s);

size_t cdecl signBlock(int index);

std::string arrayToString(int *i, int size);


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

   file >> config.logName >> config.numberOfInstructions >> config.numberOfJumps >> config.stackSize >>  config.memorySize;
   file.close();

  
   state.wasCall = false;
   state.totalBlocks = 0;
   state.completedBlocks = 0;
   state.signedBlocks = 0;


   // log file
   file.open(config.logName, std::ios::out);

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
	state.timev = time(0);
	hashInt(state.timev);

	if(file.is_open == false) {
		file.open(config.logName, std::ios::out);
	}
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


extc int _export cdecl ODBG_Pausedex(int reasonex, int dummy, t_reg *reg, DEBUG_EVENT *debugevent) {
	ulong srcsize;
	t_disasm disasm;
	uchar cmd[MAXCMDSIZE];

	if(reg == NULL)
		return 1;


	switch(reasonex) {
		
		case PP_EVENT:
				if(state.wasCall == true) {					// last instruction was call
					Block block = blocks.back();
					if(reg->ip == state.retAddr.back())		// current ip == address of instruction after call
						block.wasCalled = true;				// call was steped over
					else 
						block.wasCalled = false;			// call was steped in
					
					state.wasCall = false;					// reset flag
				}
			   

				srcsize = Readcommand(reg->ip, (char*)cmd); 

				if(srcsize != 0) {

					srcsize = Disasm(cmd, srcsize, reg->ip, DEC_UNKNOWN, &disasm, DISASM_ALL, NULL);

					if(disasm.error != 0) 
						break;
					

					if(disasm.cmdtype == C_CAL || disasm.cmdtype == C_JMP) {	// promijenit jmp jxx						// if instruction is CALL or JXX
						Block block;
						block.blockMark = state.blockMark;

						state.wasCall = true;
						state.retAddr.push_back(reg->ip + srcsize);										// add new ret address

						block.startAddress = disasm.jmpaddr;

						instructionDump(disasm.jmpaddr, 0, block.calledInstructionsDump);

						registerDump(reg, block.reg);

						block.stackDump.resize(config.stackSize);
						stackDump(reg, block.stackDump);

						checkRegValues(block.reg, block.pointers);

						block.memoryDump.resize(config.memorySize * 8);
						memoryDump(block, block.memoryDump);

						stackBaseDump(reg, block.stackBase);

						modulesDump(block.modules);

						instructionDump(disasm.ip + srcsize, 0, block.instructionDump);

						blocks.push_back(block);
						state.totalBlocks++;
						state.completeBlocks.push_back(false);
						state.signBlocks.push_back(false);
					}	
				}
	}

	return 1;
};

void cdecl modulesDump(std::vector<Module> &modules) {
	t_table *table =(t_table *) Plugingetvalue(VAL_MODULES);		// write information about all modules in the process
	t_module *tm = (t_module *) table->data.data;

	for(int i = 0; i < table->data.n; i++) {
		Module module;

		tm++;
		std::string name = tm->name;
		if(name.size() >= SHORTLEN) {
			name[SHORTLEN] = '\0';
			name.resize(SHORTLEN + 1);
		}

		module.name = name;
		module.base = tm->base;
		module.size = tm->size;
		module.codeBase = tm->codebase;
		module.codeSize = tm->codesize;
		module.dataBase = tm->database;
	}
}

void cdecl stackBaseDump(t_reg *reg, ulong &stackBase) {
	t_table *table = (t_table *)  Plugingetvalue(VAL_MEMORY);	
	t_memory *mm = (t_memory *) table->data.data;
	ulong maxAdd = 0;
	
	for(int i = 0; i < table->data.n; i++) {
		if((mm+i)->type == 0x04000000 && (mm+i)->base > maxAdd)
			maxAdd = (mm+i)->base;
	}

	stackBase = maxAdd;
}

void cdecl checkRegValues(ulong *reg, bool *pointers) {
	for(int i = 0; i < 8; i++) {
		t_memory *mem;

		mem = Findmemory(reg[i]);

		if(mem == NULL)
			pointers[i] = 0;
		else
			pointers[i] = 1;							
	}
}

void cdecl memoryDump(Block &block, std::vector<char> &dump) {
	ulong boundary = 0;

	for(int i = 0; i < 8; i++) {
		if(block.pointers[i] == 0)
			continue;

		Readmemory(&dump[boundary], block.reg[i], config.memorySize, MM_RESILENT);		
		boundary += config.memorySize;
	}

}

void cdecl stackDump(t_reg *reg, std::vector<char> &dump) {
	Readmemory(&dump[0], reg->r[4], config.stackSize, MM_RESILENT);					
}

void cdecl registerDump(t_reg *reg, ulong *r) {
	for(int i = 0; i < 8; i++) 
		r[i] = reg->r[i];
}

void cdecl instructionDump(ulong addr, uint depth, std::string &buffer) {					
	ulong srcsize;
	uchar cmd[MAXCMDSIZE]; 
	std::string dump;
	t_disasm dis;
	int i, j;

	for(i = 0; i < config.numberOfInstructions; i++) {
		srcsize = Readcommand(addr,(char*)cmd);

		if(srcsize != 0) {
			srcsize = Disasm(cmd, srcsize, addr, DEC_UNKNOWN, &dis, DISASM_ALL, NULL);

			if(dis.error != 0)
				break;

			buffer += dis.dump;

			buffer.erase(std::remove(dump.begin(), dump.end(), ' '), dump.end());
			buffer.erase(std::remove(dump.begin(), dump.end(), ':'), dump.end());

			if(depth < config.numberOfJumps) {
				if(dis.cmdtype == C_CAL || dis.cmdtype == C_JMP) {							// if instruction is CALL
					instructionDump(dis.jmpaddr, depth + 1, buffer);			// dump instructions
				}
			}

			addr += srcsize;
		}
		else
			break;
	}
};

void cdecl ODBG_Pluginmainloop(DEBUG_EVENT *debugevent) {
	if(state.completedBlocks > state.signedBlocks) {
		for(int i = 0; i < state.totalBlocks; i++) {
			if(state.completeBlocks[i] == true && state.signBlocks[i] == false) {
				if(i == 0)
					signBlock(0);
				else if(state.completeBlocks[i-1] == true && state.signBlocks[i-1] == true)
					signBlock(i);

				state.signedBlocks++;
				state.signBlocks[i] = true;
				state.lastSignature = blocks[i].blockSignature;
			}
		}
	}
}

size_t hashInt(int i) {
	 std::hash<int> intHash;

	 return intHash(i);
}

size_t hashIntArray(int *i, int size) {
	 return hashString(arrayToString(i, size));
}

std::string arrayToString(int *i, int size) {
	 std::string s;

	 for(int j = 0; j < size; j++)
		 s += std::to_string(i[j]);

	 return s;
}

size_t hashString(std::string& s) {
	std::hash<std::string> stringHash;

	return stringHash(s);
}

size_t signBlock(int index) {
	std::string block;
	Block b = blocks[index];

	block = std::to_string(b.startAddress) + std::to_string(b.blockMark) + arrayToString((int*)b.reg, 8) + std::to_string(b.stackBase) + std::to_string(b.wasCalled) + std::to_string(b.exception)
		+ b.stackDump + b.calledInstructionsDump + b.instructionDump + b.memoryDump + arrayToString((int*)b.pointers,8);

	int size = b.modules.size();
	for(int i = 0; i < size; i++) {
		Module mod = b.modules[i];

		block += (mod.name + std::to_string(mod.base) + std::to_string(mod.size) + std::to_string(mod.codeBase) + std::to_string(mod.codeSize) + std::to_string(mod.dataBase);
	}

	if(state.totalBlocks > 1)
		block += state.lastSignature;

	b.blockSignature = hashString(block);
}