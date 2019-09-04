#include <hexrays.hpp>
#include "RestoreMacroCompression.h"

extern plugin_t PLUGIN;
// Hex-Rays API pointer
hexdsp_t* hexdsp = NULL;

int idaapi init(void)
{
	if (!init_hexrays_plugin())
		return PLUGIN_SKIP; // no decompiler
	const char* hxver = get_hexrays_version();
	msg("Hex-rays version %s has been detected, %s ready to use\n", hxver, PLUGIN.wanted_name);

	InitRestoreMacroCompression();
	return PLUGIN_KEEP;
}
//--------------------------------------------------------------------------
void idaapi term(void)
{
	if (hexdsp != NULL)
	{
		UnInitRestoreMacroCompression();
	}
}
//--------------------------------------------------------------------------
bool idaapi run(size_t arg)
{
	return true;
}
//--------------------------------------------------------------------------
static const char comment[] = "";
static const char help[] = "";
static const char wanted_name[] = "Han";
static const char wanted_hotkey[] = "";
//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	0,						// plugin flags
	init,					// initialize
	term,					// terminate. this pointer may be NULL.
	run,						// invoke plugin
	comment,					// long comment about the plugin
							// it could appear in the status line
							// or as a hint
	help,					// multiline help about the plugin
	wanted_name,				// the preferred short name of the plugin
	wanted_hotkey			// the preferred hotkey to run the plugin
};
