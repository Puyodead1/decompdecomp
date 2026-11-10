/* Demo Quest's DLL build: a function only the DLL has, which its program imports and calls, so what the run returns
 * depends on the DLL's code (a relinked DLL that's wrong shows). Written for decompdecomp (CC0). */
#include "game.h"

s32 dll_bonus(s32 total) {
    return clamp_s32(total, -1000, 1000) + entity_default_hp((s16)(total & 3));
}
