/* Demo Quest GC's colour helpers, the file after mathx.c (CC0): its own copies of 0.5f and the int-to-float double
 * say it's another file. */

float tint(float x, int n)
{
    return x * 2.5f + (float)n;
}

float dim(float x)
{
    return x * 0.5f;
}
