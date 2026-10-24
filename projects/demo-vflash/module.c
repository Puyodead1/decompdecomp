/* Demo Quest V.Flash game module (A01): a level, loaded over the others' addresses, that calls the firmware's game
 * functions by their address. Written for decompdecomp (CC0). */
#include "game.h"

s32 clamp_s32(s32 v, s32 lo, s32 hi);
void add_score(s32 points);
void game_tick(void);

static s32 level_time;

s32 level_bonus(s32 level) {
    return clamp_s32(level * 250 - level_time, 0, 5000);
}

void level_run(void) {
    s32 i;

    for (i = 0; i < 60; i++) {
        game_tick();
        level_time++;
    }
    add_score(level_bonus(1));
}
