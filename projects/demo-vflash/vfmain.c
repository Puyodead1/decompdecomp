/* Demo Quest V.Flash main loop: the firmware's (FA's) side of the demo. Written for decompdecomp (CC0). */
#include "game.h"

void game_tick(void);
s32 count_alive_entities(void);

volatile s32 g_frames;
volatile s32 g_alive;

void demo_main(void) {
    for (;;) {
        game_tick();
        g_alive = count_alive_entities();
        g_frames++;
    }
}
