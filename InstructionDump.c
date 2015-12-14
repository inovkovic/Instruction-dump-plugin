#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>

#include "Plugin.h"

struct Configuration {
	char logName[10];
	uint numberOfInstructions;	// how many instructions to read
	uint numberOfJumps;			// how deep is recursion going to be
	bool recordEntrance;		// whether to record steping in CALL instruction
	bool recordRegMod;			// whether to record if registers were modified by user
	bool recordReg;				// whether to record register values
};

struct State {
	std::vector<uint> retAddr;				//	return addresses when CALL is encountered
	bool stepIn;							//	1 - command was STEP_IN 0 - command was STEP_OVER
	std::vector<bool> regMod;				//  any register modified by user
	bool wasCall;							//	last instruction was CALL
};

HINSTANCE        hinst;                // DLL instance
HWND             hwmain;               // Handle of main OllyDbg window

Configuration config;
State		  state;

FILE *file;


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
   file = fopen("instDump.conf", "r");
   fscanf(file, "%s %lu %lu %d %d %d", config.logName, &config.numberOfInstructions, &config.numberOfJumps, &config.recordEntrance, &config.recordRegMod, &config.recordReg);
   fclose(file);

   state.stepIn = false;
   state.wasCall = false;


   // log file
   file = fopen(config.logName, "w");

   fprintf(file, "%lu %lu %d %d %d\n", config.numberOfInstructions, config.numberOfJumps, config.recordEntrance, config.recordRegMod, config.recordReg);

   Addtolist(0,0,"Instruction dump plugin v 0.1");
   Addtolist(0,-1,"  Copyright (C) 2015 Igor Novkovic");
 
   return 0;
};

extc void _export cdecl ODBG_Plugindestroy(void) {
	fclose(file);
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
	file = fopen(config.logName, "w");
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

		if(state.wasCall == true) {
			if(reg->ip == state.retAddr.back())
				state.stepIn = 0;
			else {
				state.stepIn = 1;
				state.regMod.push_back(false);
			}
			state.wasCall = false;
		}

		if(state.retAddr.size() != 0) {
			bool modified = state.regMod.back();
			state.regMod.pop_back();

			if(modified == false && reg->modified == 1) {
				modified = true;
				fprintf(file, "1\n");
			}

			state.regMod.push_back(modified);

			if(reg->ip == state.retAddr.back()) {
				state.retAddr.pop_back();

				/*if(config.recordRegMod == true)
					fprintf(file, "%d\n", state.regMod.back());*/

				if(config.recordRegMod == false)
					fprintf(file, "0\n");

				state.regMod.pop_back();
			}
		}
		
		
		srcsize = Readcommand(reg->ip, (char*)cmd); 

		if(srcsize != 0) {

			srcsize = Disasm(cmd, srcsize, reg->ip, DEC_UNKNOWN, &disasm, DISASM_ALL, NULL);

			if(disasm.error != 0)
				break;

			if(disasm.cmdtype == C_CAL) {							// if instruction is CALL
				state.wasCall = true;
				state.retAddr.push_back(reg->ip + srcsize);			// add new ret address
				recordInstructions(&disasm, 0);						// dump instructions
				fprintf(file, "\n");
			}

			return 1;
		}
	}
	return 0;
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
				if(dis.cmdtype == C_CAL)							// if instruction is CALL
					recordInstructions(&dis, depth + 1);			// dump instructions
			}

			ip += srcsize;
		}
		else
			break;
	}

	fprintf(file, "%s", dump.c_str());
};