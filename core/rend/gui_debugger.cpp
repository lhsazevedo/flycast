
#include "gui_debugger.h"

#include "types.h"
#include "debug/debug_agent.h"
#include "emulator.h"
#include "gui_util.h"
#include "hw/sh4/sh4_if.h"
#include "imgui/imgui.h"
#include "input/gamepad_device.h"
#include "sh4asm/sh4asm_core/disas.h"

#define DISAS_LINE_LEN 128
static char sh4_disas_line[DISAS_LINE_LEN];

static void disas_emit(char ch) {
	size_t len = strlen(sh4_disas_line);
    if (len >= DISAS_LINE_LEN - 1)
        return; // no more space
    sh4_disas_line[len] = ch;
}

void gui_debugger_disasm()
{
    u32 pc = *GetRegPtr(reg_nextpc);

	ImGui::SetNextWindowPos(ImVec2(16, 16), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ScaledVec2(350, 0), ImGuiCond_FirstUseEver);
	ImGui::Begin("Disassembly", NULL);

	bool running = emu.running();

	if (!running)
	{
		ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
	}
	if (ImGui::Button("Suspend"))
	{
		// config::DynarecEnabled = false;
		debugAgent.interrupt();
	}
	if (!running)
	{
		ImGui::PopItemFlag();
        ImGui::PopStyleVar();
	}

	if (running)
	{
		ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
	}

	ImGui::SameLine();
	if (ImGui::Button("Step"))
	{
		debugAgent.step();
	}

	ImGui::SameLine();
	if (ImGui::Button("Resume"))
	{
		debugAgent.step();
		emu.start();
	}
	if (running)
	{
		ImGui::PopItemFlag();
        ImGui::PopStyleVar();
	}

	ImGui::SameLine();
	if (ImGui::Button("Close"))
	{
		gui_state = GuiState::Closed;
		GamepadDevice::load_system_mappings();
		emu.start();
	}


	ImGui::PushItemWidth(80);
	static char bpBuffer[9] = "";
	ImGui::InputText("##bpAddr", bpBuffer, 9, ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase);
	ImGui::PopItemWidth();

	ImGui::SameLine();
	if (ImGui::Button("Add BP"))
	{
		char* tmp;
		long bpaddr = strtoul(bpBuffer, &tmp, 16);
		debugAgent.insertMatchpoint(0, (u32) bpaddr, 2);
	}

	ImGui::PushItemWidth(80);
	static char patchAddressBuffer[8 + 1] = "";
	static char patchWordBuffer[4 + 1] = "";
	ImGui::InputText("##patchAddr", patchAddressBuffer, 8 + 1, ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase);
	ImGui::SameLine();
	ImGui::InputText("##patchWord", patchWordBuffer, 4 + 1, ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase);
	ImGui::PopItemWidth();

	ImGui::SameLine();
	if (ImGui::Button("Write"))
	{
		char* tmp;
		long patchAddress = strtoul(patchAddressBuffer, &tmp, 16);
		long patchWord = strtoul(patchWordBuffer, &tmp, 16);
		// debugAgent.insertMatchpoint(0, (u32) patchAddress, 2);
		WriteMem16_nommu(patchAddress, patchWord);
	}

	// if (Sh4cntx.pc == 0x8C010000 || Sh4cntx.spc == 0x8C010000)
	// {
	// 	NOTICE_LOG(COMMON, "1ST_READ.bin entry");
	// 	dc_stop();
	// }

	ImGuiIO& io = ImGui::GetIO();
	ImFontAtlas* atlas = io.Fonts;
	ImFont* defaultFont = atlas->Fonts[1];

	ImGui::PushFont(defaultFont);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));


	for (size_t i = 0; i < 20; i++)
	{
		const u32 addr = pc + i * 2;

		u16 instr = ReadMem16_nommu(addr);

		auto it = debugAgent.breakpoints.find(addr);
		const bool isBreakpoint = it != debugAgent.breakpoints.end();

		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0,2));
		if (isBreakpoint) {
			ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 0, 0, 255));
			ImGui::Text("B ");
			if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
				debugAgent.removeMatchpoint(0, addr, 2);
			}

			ImGui::PopStyleColor();

			instr = it->second.savedOp;
		} else {
			ImGui::Text("  ");
			if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
				debugAgent.insertMatchpoint(0, addr, 2);
			}
		}
		ImGui::SameLine();
		ImGui::PopStyleVar();

		char buf [64];

		memset(sh4_disas_line, 0, sizeof(sh4_disas_line));
		sh4asm_disas_inst(instr, disas_emit, addr);
		//dasmbuf = decode(instr, pc);
		sprintf(buf, "%08X:", (u32) addr);
		ImGui::Text(buf);
		ImGui::SameLine();
		ImGui::TextDisabled("%04X", instr);
		ImGui::SameLine();
		ImGui::Text(sh4_disas_line);
	}

	ImGui::PopFont();
	ImGui::PopStyleVar();
	ImGui::End();
}


u32 memoryDumpAddr = 0x8c010000;

void gui_debugger_memdump()
{
    ImGui::SetNextWindowPos(ImVec2(600, 450), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ScaledVec2(540, 0));
	ImGui::Begin("Memory Dump", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);

	ImGui::PushItemWidth(80);
	static char memDumpAddrBuf[8 + 1] = "";
	ImGui::InputText("##memDumpAddr", memDumpAddrBuf, 8 + 1, ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase);
	ImGui::PopItemWidth();

	ImGui::SameLine();
	if (ImGui::Button("Go"))
	{
		char* tmp;
		memoryDumpAddr = (strtoul(memDumpAddrBuf, &tmp, 16) / 16) * 16;
	}

	ImGui::SameLine();
	if (ImGui::Button("---"))
	{
		memoryDumpAddr -= 16 * 16 * 16;
	}

	ImGui::SameLine();
	if (ImGui::Button("--"))
	{
		memoryDumpAddr -= 16 * 16;
	}

	ImGui::SameLine();
	if (ImGui::Button("-"))
	{
		memoryDumpAddr -= 16;
	}

	ImGui::SameLine();
	if (ImGui::Button("+"))
	{
		memoryDumpAddr += 16;
	}

	ImGui::SameLine();
	if (ImGui::Button("++"))
	{
		memoryDumpAddr += 16 * 16;
	}

	ImGui::SameLine();
	if (ImGui::Button("+++"))
	{
		memoryDumpAddr += 16 * 16 * 16;
	}

    ImGuiIO& io = ImGui::GetIO();
	ImFontAtlas* atlas = io.Fonts;
	ImFont* defaultFont = atlas->Fonts[1];

	ImGui::PushFont(defaultFont);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));

	char hexbuf[256];
	for (size_t i = 0; i < 16; i++) {
		memset(hexbuf, 0, sizeof(hexbuf));
		size_t hexbuflen = 0;

		hexbuflen += sprintf(hexbuf, "%08X: ", memoryDumpAddr + i * 16);

		for (size_t j = 0; j < 16; j++) {
			int byte = ReadMem8_nommu(memoryDumpAddr + i * 16 + j);
			hexbuflen += sprintf(hexbuf + hexbuflen, "%02X", byte);

			if ((j + 1) % 4 == 0) {
				hexbuflen += sprintf(hexbuf + hexbuflen, "|");
			} else {
				hexbuflen += sprintf(hexbuf + hexbuflen, " ");
			}
		}
		hexbuflen += sprintf(hexbuf + hexbuflen, " ");
		for (size_t j = 0; j < 16; j++) {
			int c = ReadMem8_nommu(memoryDumpAddr + i * 16 + j);
			// fprintf(fp_out, "%c", )
			hexbuflen += sprintf(hexbuf + hexbuflen, "%c", (c >= 33 && c <= 126 ? c : '.'));
		}

		ImGui::Text("%s", hexbuf);
	}

	ImGui::PopFont();
	ImGui::PopStyleVar();
	ImGui::End();
}

void gui_debugger_breakpoints()
{
    ImGuiIO& io = ImGui::GetIO();
	ImFontAtlas* atlas = io.Fonts;
	ImFont* defaultFont = atlas->Fonts[1];

    ImGui::SetNextWindowPos(ImVec2(700, 16), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ScaledVec2(150, 0));
	ImGui::Begin("Breakpoints", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
	ImGui::PushFont(defaultFont);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));

	auto it = debugAgent.breakpoints.begin();

	while (it != debugAgent.breakpoints.end())
    {
		ImGui::Text("0x%08x", it->first);

		it++;
    }

	ImGui::PopStyleVar();
	ImGui::PopFont();
	ImGui::End();
}

void gui_debugger_sh4()
{
    ImGuiIO& io = ImGui::GetIO();
	ImFontAtlas* atlas = io.Fonts;
	ImFont* defaultFont = atlas->Fonts[1];

    ImGui::SetNextWindowPos(ImVec2(900, 16), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ScaledVec2(260, 0));
	ImGui::Begin("SH4", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
	ImGui::PushFont(defaultFont);

	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));

    u32 pc = *GetRegPtr(reg_nextpc);

	u32 regValue;
	f32 floatRegValue;

	ImGui::Text("PC:  %08X", pc);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
		memoryDumpAddr = (pc / 16) * 16;
	}

	ImGui::SameLine();
	regValue = *GetRegPtr(reg_pr);
	ImGui::Text(" PR:      %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	regValue = *GetRegPtr(reg_r0);
	ImGui::Text("r0:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_0);
	ImGui::Text(" fr0:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r1);
	ImGui::Text("r1:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_1);
	ImGui::Text(" fr1:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r2);
	ImGui::Text("r2:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_2);
	ImGui::Text(" fr2:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r3);
	ImGui::Text("r3:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_3);
	ImGui::Text(" fr3:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r4);
	ImGui::Text("r4:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_4);
	ImGui::Text(" fr4:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r5);
	ImGui::Text("r5:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_5);
	ImGui::Text(" fr5:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r6);
	ImGui::Text("r6:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_6);
	ImGui::Text(" fr6:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r7);
	ImGui::Text("r7:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_7);
	ImGui::Text(" fr7:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r8);
	ImGui::Text("r8:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_8);
	ImGui::Text(" fr8:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r9);
	ImGui::Text("r9:  %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_9);
	ImGui::Text(" fr9:  %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r10);
	ImGui::Text("r10: %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_10);
	ImGui::Text(" fr10: %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r11);
	ImGui::Text("r11: %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_11);
	ImGui::Text(" fr11: %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r12);
	ImGui::Text("r12: %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_12);
	ImGui::Text(" fr12: %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r13);
	ImGui::Text("r13: %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_13);
	ImGui::Text(" fr13: %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r14);
	ImGui::Text("r14: %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_14);
	ImGui::Text(" fr14: %11.5f", floatRegValue);

	regValue = *GetRegPtr(reg_r15);
	ImGui::Text("r15: %08X", regValue);
	if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && (regValue & 0xFF000000) == 0x8c000000) {
		memoryDumpAddr = (regValue / 16) * 16;
	}

	ImGui::SameLine();
	floatRegValue = *GetFloatRegPtr(reg_fr_15);
	ImGui::Text(" fr15: %11.5f", floatRegValue);

	ImGui::PopStyleVar();
	ImGui::PopFont();
	ImGui::End();
}

void gui_debugger_tbg()
{
    ImGuiIO& io = ImGui::GetIO();
	ImFontAtlas* atlas = io.Fonts;
	ImFont* defaultFont = atlas->Fonts[1];

    ImGui::SetNextWindowPos(ImVec2(1200, 16), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ScaledVec2(260, 0));

	ImGui::Begin("TBG Tasks", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
	ImGui::PushFont(defaultFont);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));

	ImGui::Text("Array 1 / Array 2");

	for (int i = 0; i < 17; i++) {

		u32 action = *((u32 *) GetMemPtr(0x8c1ba3c8 + i * 32, 0));
		auto it = knownTasks.find(action);
		if (it != knownTasks.end()) {
			ImGui::Text("%s", it->second.c_str());
		} else {
			ImGui::Text("0x%08x", action);
		}

		if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
			WriteMem32_nommu(0x8c1ba3c8 + i * 32, 0xffffffff);
		}

		action = *((u32 *) GetMemPtr(0x8c1ba5e8 + i * 32, 0));
		it = knownTasks.find(action);
		ImGui::SameLine();
		if (it != knownTasks.end()) {
			ImGui::Text("%s", it->second.c_str());
		} else {
			ImGui::Text("0x%08x", action);
		}

		if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
			WriteMem32_nommu(0x8c1ba5e8 + i * 32, 0xffffffff);
		}
	}

	ImGui::SetNextWindowPos(ImVec2(700, 128), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ScaledVec2(260, 0));

	ImGui::PopStyleVar();
	ImGui::PopFont();
	ImGui::End();

	ImGui::Begin("TBG Bus", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize);
	ImGui::PushFont(defaultFont);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8,2));

	int busInt;
	f32 busFloat;

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x070, 0));
	ImGui::Text("0x070 dst: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x074, 0));
	ImGui::Text("0x074 ang: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x078, 0));
	ImGui::Text("0x078 acc: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x07c, 0));
	ImGui::Text("0x07c ang: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x080, 0));
	ImGui::Text("0x080 blk: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x250, 0));
	ImGui::Text("0x250 ang: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x258, 0));
	ImGui::Text("0x258 ang: %d", busInt);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x268, 0));
	ImGui::Text("0x268 mirror: %d", busInt);

	busFloat = *((f32 *) GetMemPtr(0x8c1bb9d0 + 0x27c, 0));
	ImGui::Text("0x27c spd: %11.5f", busFloat);

	ImGui::Text("0x280[] acc hist: [", busFloat);
	busFloat = *((f32 *) GetMemPtr(0x8c1bb9d0 + 0x280, 0));
	ImGui::Text("  0: %11.5f", busFloat);
	busFloat = *((f32 *) GetMemPtr(0x8c1bb9d0 + 0x284, 0));
	ImGui::Text("  1: %11.5f", busFloat);
	busFloat = *((f32 *) GetMemPtr(0x8c1bb9d0 + 0x288, 0));
	ImGui::Text("  2: %11.5f", busFloat);
	busFloat = *((f32 *) GetMemPtr(0x8c1bb9d0 + 0x28c, 0));
	ImGui::Text("  3: %11.5f", busFloat);
	ImGui::Text("]", busFloat);

	busInt = *((s32 *) GetMemPtr(0x8c1bb9d0 + 0x2f4, 0));
	ImGui::Text("0x2f4 gear: %d", busInt);

	ImGui::PopStyleVar();
	ImGui::PopFont();
	ImGui::End();
}
