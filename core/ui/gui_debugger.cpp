/*
	Copyright 2024 flyinghead

	This file is part of Flycast.

    Flycast is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Flycast is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Flycast.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "gui_debugger.h"
#include "emulator.h"
#include "gui_util.h"
#include "imgui.h"
#include "hw/sh4/sh4_mem.h"
#include <capstone/capstone.h> 

// TODO:Use namespace

// TODO: Organize variables
static csh capstoneHandle;
extern ImFont *monospaceFont;

// TODO: Review prefix
enum DisassemblyEntryType {
	DisassemblyEntryType_Instruction,
	DisassemblyEntryType_Data,
};

struct DisassemblyEntry {
	uint32_t address;
	DisassemblyEntryType type;
	std::string instruction;
};

static std::vector<DisassemblyEntry> disassembly;

static void draw_execution_bar()
{
	ImGui::SetNextWindowPos(ScaledVec2(10, 10), ImGuiCond_FirstUseEver);
	ImGui::Begin("Execution", NULL, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize);

	if (emu.running()) {
		if (ImGui::Button("Suspend", ScaledVec2(80, 0))) {
			emu.stop(); // TODO: Use debug agent
			// The debugger will be now rendered as GUI
			gui_setState(GuiState::Debugger);
		}
	} else if (ImGui::Button("Resume", ScaledVec2(80, 0))) {
		emu.start(); // TODO: Use debug agent
		// The debugger will be now rendered as OSD
		gui_setState(GuiState::Closed);
	}

	{
		// DisabledScope _{true};
		ImGui::SameLine();
		ImGui::Button("Step Into");
	}

	{
		// DisabledScope _{true};
		ImGui::SameLine();
		ImGui::Button("Step Over");
	}

	{
		// DisabledScope _{true};
		ImGui::SameLine();
		ImGui::Button("Step Out");
	}

	ImGui::End();
}

/**
 * Custom wrapper for cs_disasm_iter that does not modify arguments.
 */
static bool fc_disasm_iter(csh handle, const uint8_t *code, uint64_t address, cs_insn *insn)
{
	const uint8_t *codeLocal = code;
	size_t instructionSize = 2;
	return cs_disasm_iter(handle, &codeLocal, &instructionSize, &address, insn);
}

static void draw_disassembly_window()
{
	// printf("draw_disassembly_window\n");
	ImGui::SetNextWindowPos(ScaledVec2(10, 100), ImGuiCond_FirstUseEver);
	ImGui::Begin("Disassembly", NULL, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize);

	/* 
		TODO:
		- Do not disasm while running
		- v1: Initial implementation
			- Disasm everything on button click
			- Simple disasm
			- Render rich disasm for the current view onl
			- Breakpoint on single click
		- v2: ...
			- Basic blocks
			- Labels
			- Comments
	 */

	// if (ImGui::Button("Analyze")) {
	// 	//analyse();
	// }

	// TODO: Review var names
	size_t instructionSize = 2;
	cs_insn *insn = cs_malloc(capstoneHandle);
	uint64_t address = 0;

	ImGui::PushFont(monospaceFont);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));

	u32 pc = Sh4cntx.pc;
	for (size_t i = 0; i < 20; i++)
	{
		u32 addr = (pc & 0x1fffffff) + i * 2;
		const u8* code = GetMemPtr(addr, 0);

		u16 instr = ReadMem16_nommu(addr);

		//auto it = debugAgent.breakpoints[DebugAgent::Breakpoint::Type::BP_TYPE_SOFTWARE_BREAK].find(addr);
		//const bool isBreakpoint = it != debugAgent.breakpoints[DebugAgent::Breakpoint::Type::BP_TYPE_SOFTWARE_BREAK].end();

		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0,2));
		// if (isBreakpoint) {
		// 	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));
		// 	ImGui::Text("B ");
		// 	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
		// 		debugAgent.removeMatchpoint(DebugAgent::Breakpoint::BP_TYPE_SOFTWARE_BREAK, addr, 2);
		// 	}

		// 	ImGui::PopStyleColor();

		// 	instr = it->second.savedOp;
		// } else {
			ImGui::Text("  ");
		// 	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
		// 		debugAgent.insertMatchpoint(DebugAgent::Breakpoint::BP_TYPE_SOFTWARE_BREAK, addr, 2);
		// 	}
		// }
		ImGui::SameLine();
		ImGui::PopStyleVar();

		char buf [64];

		//memset(sh4_disas_line, 0, sizeof(sh4_disas_line));
		//sh4asm_disas_inst(instr, disas_emit, addr);
		//dasmbuf = decode(instr, pc);
		//sprintf(buf, "%08X:", (u32) addr);
		ImGui::Text("%08X:", (u32) addr);
		//ImGui::Text("%s", buf);
		ImGui::SameLine();
		ImGui::TextDisabled("%04X", instr);
		ImGui::SameLine();

		if (!fc_disasm_iter(capstoneHandle, code, addr, insn)) {
			ImGui::Text("Invalid instruction");
		} else {
			bool isControlFlowInstruction = false;

			for (size_t j = 0; j < insn->detail->groups_count; j++) {
				uint8_t group = insn->detail->groups[j];
				uint insnId = insn->id;
				
				isControlFlowInstruction = 
					group == CS_GRP_CALL
					|| group == CS_GRP_JUMP
					|| group == CS_GRP_RET
					|| group == CS_GRP_IRET
					|| group == CS_GRP_BRANCH_RELATIVE
					|| insnId == SH_INS_RTS
					|| insnId == SH_INS_RTE
					|| insnId == SH_INS_RTS_N
					|| insnId == SH_INS_RTV_N;	
				
				if (isControlFlowInstruction)
					break;
			}

			if (isControlFlowInstruction)
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));

			ImGui::Text("%-8s", insn->mnemonic);

			if (isControlFlowInstruction)
				ImGui::PopStyleColor();
			
			ImGui::SameLine();
			ImGui::Text("%s", insn->op_str);

			if (isControlFlowInstruction)
				ImGui::NewLine();
		}
		//printf("%s\t%s", insn->mnemonic, insn->op_str);
	}

	cs_free(insn, 1);

	ImGui::PopStyleVar();
	ImGui::PopFont();

	ImGui::End();
}

void gui_debugger_init()
{
	if (cs_open(CS_ARCH_SH, (cs_mode) (CS_MODE_LITTLE_ENDIAN | CS_MODE_SH4 | CS_MODE_SHFPU), &capstoneHandle) != CS_ERR_OK) {
		ERROR_LOG(COMMON, "Failed to open Capstone: %s", cs_strerror(cs_errno(capstoneHandle)));
		return;
	}

	cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

void gui_debugger_term()
{
	if (capstoneHandle) {
		cs_close(&capstoneHandle);
	}
}

void gui_debugger()
{
	draw_execution_bar();
	draw_disassembly_window();
}
