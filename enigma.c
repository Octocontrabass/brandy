#include <stdint.h>
#include <stddef.h>
#include "enigma.h"

static uint8_t a[0x100];
static uint8_t b[0x100];
static uint8_t c[0x100];

/* This algorithm has a weakness that causes it to generate the same seed even
 * if the first two letters of the product code are transposed. */
void maketables( const uint8_t * const product )
{
    int32_t seed = 123;
    for( size_t i = 0; i < 5; i++ )
    {
        seed = (seed * product[i]) + i; // <-- here
    }
    for( size_t i = 0; i < 0x100; i++ )
    {
        a[i] = i;
        c[i] = 0;
    }
    for( size_t i = 0; i < 0x100; i++ )
    {
        seed = seed * 5 + product[(i % 3) + 2]; // <-- here
        uint16_t random = seed % 65521;
        uint16_t k = 0xff - i;
        uint16_t ic = (random & 0xff) % (k + 1);
        uint8_t temp = a[k];
        a[k] = a[ic];
        a[ic] = temp;
        if( c[k] == 0 )
        {
            ic = (random >> 8) % k;
            while( c[ic] != 0 )
            {
                ic = (ic + 1) % k;
            }
            c[k] = ic;
            c[ic] = k;
        }
    }
    for( size_t i = 0; i < 0x100; i++ )
    {
        b[a[i]] = i;
    }
    return;
}

void enigma( const uint8_t * const in, uint8_t * const out, size_t length )
{
    for( size_t i = 0; i < length; i++ )
    {
        out[i] = b[(c[(a[(in[i] + i) & 0xff] + (i >> 8)) & 0xff] - (i >> 8)) & 0xff] - i;
    }
    return;
}
