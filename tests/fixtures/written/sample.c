/* A small DLL for sootmark-pe's tests: named, ordinal-only and forwarded
   exports, imports by name and by ordinal, a delay-loaded import, a
   version resource, a load configuration directory and a CodeView (RSDS)
   debug entry. Built by build.sh. */
#include <windows.h>

/* Imported by ordinal 5 from helper.dll (helper.def, NONAME). */
__declspec(dllimport) int helper_by_ordinal(void);

/* The load configuration directory: the linker points its data directory
   at this symbol. Only its size and time stamp are set. */
const IMAGE_LOAD_CONFIG_DIRECTORY64 _load_config_used = {
    sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64),
    0x5F5E1000, /* TimeDateStamp: 2020-09-13T12:26:40Z */
};

int sample_add(int a, int b) { return a + b; }

int sample_version(void) { return (int)GetCurrentProcessId() + helper_by_ordinal(); }

int sample_hidden(void) { return 7; }

/* user32.dll is delay-loaded (dlltool --output-delaylib). */
void sample_greet(void) { MessageBoxA(NULL, "hello", "sample", MB_OK); }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
