/* Demo Quest GC's float helpers, one source file (CC0). With shade.c after it, the evidence of where a GameCube game's
 * files end: CodeWarrior pools each file's float constants on their own (.sdata2), so the functions here share
 * 1.5f and the int-to-float double, and shade.c has its own copies (tests/test_gc.py, forks/pools.py). */

float scale_add(float x, int n)
{
    return x * 1.5f + (float)n;
}

float scale_sub(float x, int n)
{
    return x * 1.5f - (float)n;
}

float halve(float x)
{
    return x * 0.5f;
}
