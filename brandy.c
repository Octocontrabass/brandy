#include <inttypes.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "enigma.h"

void * checked_malloc( size_t size )
{
    void * temp = malloc( size );
    if( !temp )
    {
        fprintf( stderr, "Failed to allocate %zu bytes.\n", size );
        exit( 0 );
    }
    return temp;
}

static void keyencrypt( uint8_t * const key )
{
    uint8_t current = 0;
    for( size_t i = 0; i < 8; i++ )
    {
        key[7 - i] += current;
        current = (key[7 - i] + current) % 26;
        if( key[7 - i] < 'a' )
        {
            key[7 - i] += 26;
        }
        else if( key[7 - i] > 'z' )
        {
            key[7 - i] -= 26;
        }
    }
    return;
}

static void keydecrypt( uint8_t * const key )
{
    uint8_t current = 0;
    for( size_t i = 0; i < 8; i++ )
    {
        key[7 - i] -= current;
        current = (key[7 - i] + current * 2) % 26;
        if( key[7 - i] < 'a' )
        {
            key[7 - i] += 26;
        }
        else if( key[7 - i] > 'z' )
        {
            key[7 - i] -= 26;
        }
    }
    return;
}

static uint16_t sum( const uint8_t * const data, size_t count )
{
    uint16_t checksum = 0;
    for( size_t i = 0; i < count; i++ )
    {
        checksum += data[i];
        checksum = (checksum << 1) | (checksum >> 15);
    }
    return checksum;
}

static void keysum( const uint8_t * const key, uint8_t * const charsum )
{
    uint16_t checksum = sum( key, 15 ); 
    checksum = (checksum << (key[8] & 0xf)) | (checksum >> (-key[8] & 0xf));
    charsum[1] = (checksum % 26) + 'a';
    charsum[0] = ((checksum / 26) % 26) + 'a';
    return;
}

int main( const int argc, const char * const * const argv )
{
    if( argc < 2 )
    {
        fprintf( stdout, "Usage: %s [function] [arguments]\n\n"
        "Functions:\n"
        //"    brand ----- (todo)\n"
        "    crack ----- Find the product code from an encrypted file.\n"
        //"    debrand --- (todo)\n"
        //"    encrypt --- Encrypt a file, without debranding it.\n"
        "    generate -- Create an activation key.\n"
        "    unencrypt - Decrypt a file, without branding it.\n"
        "    verify ---- Check a serial number/activation key combination.\n",
        argv[0] );
        return 0;
    }
    switch( argv[1][0] )
    {
        case 'C':
        case 'c':
            if( argc != 3 )
            {
                fprintf( stdout, "Usage: %s crack [file]\n\n"
                "Find all product codes that appear to correctly decrypt an encrypted file.\n",
                argv[0] );
                return 0;
            }
            {
                uint8_t in[0x100];
                uint8_t out[0x100];
                FILE * infile = fopen( argv[2], "rb" );
                if( !infile )
                {
                    fprintf( stderr, "Can't open file: %s\n", argv[2] );
                    return 0;
                }
                fread( in, 0x100, 1, infile );
                if( in[0xff] != 0x84 )
                {
                    fprintf( stderr, "File is not encrypted: %s\n", argv[2] );
                    return 0;
                }
                uint16_t checksum = (uint16_t)in[0xfd] << 8 | in[0xfe];
                fprintf( stdout, "Checksum: %04" PRIX16 "\n"
                "Size: %" PRIu32 "\n"
                "Product codes:", checksum,
                (uint32_t)in[0xf9] << 24 | (uint32_t)in[0xfa] << 16 |
                (uint32_t)in[0xfb] << 8 | in[0xfc] );
                fread( in, 0x100, 1, infile );
                for( uint8_t i = 'a'; i <= 'z'; i++ )
                {
                    for( uint8_t j = 'a'; j <= 'z'; j++ )
                    {
                        for( uint8_t k = 'a'; k <= 'z'; k++ )
                        {
                            uint8_t product[5] = { i, j, k, 'T', 'b' };
                            maketables( product );
                            enigma( in, out, 0x100 );
                            if( sum( out, 0x100 ) == checksum )
                            {
                                product[3] = 0;
                                fprintf( stdout, " %s", product );
                            }
                        }
                    }
                }
            }
            fprintf( stdout, "\n" );
            return 0;
        case 'G':
        case 'g':
            if( argc != 4 )
            {
                fprintf( stdout, "Usage: %s generate [serial] [product]\n\n"
                "Create a new activation key from a serial number and product code.\n",
                argv[0] );
                return 0;
            }
            if( strlen( argv[2] ) != 9 || strlen( argv[3] ) != 3 )
            {
                fprintf( stderr, "Serial numbers are always 9 characters.\n"
                "Product codes are always 3 letters.\n" );
                return 0;
            }
            for( size_t i = 0; i < 3; i++ )
            {
                if( !islower( argv[3][i] ) )
                {
                    fprintf( stderr, "Product codes are always lowercase.\n" );
                    return 0;
                }
            }
            {
                uint8_t key[18];
                memcpy( &key[0], argv[2], 9 );
                memcpy( &key[9], argv[3], 3 );
                memcpy( &key[12], "aaa", 3 ); // todo: what is this?
                keysum( &key[0], &key[15] );
                keyencrypt( &key[9] );
                key[17] = 0;
                fprintf( stdout, "Activation key: %s\n", &key[9] );
            }
            return 0;
        case 'U':
        case 'u':
            if( argc != 5 )
            {
                fprintf( stdout, "Usage: %s unencrypt [key] [input] [output]\n\n"
                "Decrypt an encrypted file without branding it, using either an activation key\n"
                "or a product code.\n",
                argv[0] );
                return 0;
            }
            {
                uint8_t * in;
                uint8_t * out;
                FILE * infile;
                FILE * outfile;
                uint8_t product[5] = { 0, 0, 0, 'T', 'b' };
                uint16_t checksum;
                uint32_t size;
                if( strlen( argv[2] ) == 3 )
                {
                    for( size_t i = 0; i < 3; i++ )
                    {
                        if( !islower( argv[2][i] ) )
                        {
                            fprintf( stderr, "Product codes are always lowercase.\n" );
                            return 0;
                        }
                    }
                    memcpy( product, argv[2], 3 );
                }
                else if( strlen( argv[2] ) == 8 )
                {
                    for( size_t i = 0; i < 8; i++ )
                    {
                        if( !islower( argv[2][i] ) )
                        {
                            fprintf( stderr, "Activation keys are always lowercase.\n" );
                            return 0;
                        }
                    }
                    memcpy( product, argv[2], 3 );
                    uint8_t key[8];
                    memcpy( key, argv[2], 8 );
                    keydecrypt( key );
                    memcpy( product, key, 3 );
                }
                else
                {
                    fprintf( stderr, "Activation keys are always 8 letters. Product codes are always 3 letters.\n" );
                    return 0;
                }
                infile = fopen( argv[3], "rb" );
                if( !infile )
                {
                    fprintf( stderr, "Can't open file: %s\n", argv[3] );
                    return 0;
                }
                outfile = fopen( argv[4], "wb" );
                if( !outfile )
                {
                    fprintf( stderr, "Can't open file: %s\n", argv[4] );
                    return 0;
                }
                in = checked_malloc( 0x100 );
                fread( in, 0x100, 1, infile );
                if( in[0xff] != 0x84 )
                {
                    fprintf( stderr, "File is not encrypted: %s\n", argv[3] );
                    return 0;
                }
                checksum = (uint16_t)in[0xfd] << 8 | in[0xfe];
                size = (uint32_t)in[0xf9] << 24 | (uint32_t)in[0xfa] << 16 |
                    (uint32_t)in[0xfb] << 8 | in[0xfc];
                free( in );
                in = checked_malloc( size );
                out = checked_malloc( size );
                maketables( product );
                fread( in, size, 1, infile );
                enigma( in, out, size );
                if( sum( out, 0x100 ) != checksum )
                {
                    fprintf( stdout, "Checksum doesn't match!\n" );
                }
                fwrite( out, size, 1, outfile );
            }
            return 0;
        case 'V':
        case 'v':
            if( argc != 4 )
            {
                fprintf( stdout, "Usage: %s verify [serial] [key]\n\n"
                "Find out if a serial number/activation key combination is valid, and see the\n"
                "product code it contains.\n",
                argv[0] );
                return 0;
            }
            if( strlen( argv[2] ) != 9 || strlen( argv[3] ) != 8 )
            {
                fprintf( stderr, "Serial numbers are always 9 characters.\n"
                "Activation keys are always 8 letters.\n" );
                return 0;
            }
            for( size_t i = 0; i < 8; i++ )
            {
                if( !islower( argv[3][i] ) )
                {
                    fprintf( stderr, "Activation keys are always lowercase.\n" );
                    return 0;
                }
            }
            {
                uint8_t key[17];
                uint8_t sum[2];
                memcpy( &key[0], argv[2], 9 );
                memcpy( &key[9], argv[3], 8 );
                keydecrypt( &key[9] );
                keysum( key, sum );
                if( memcmp( &key[12], "aaa", 3 ) ) // todo: what is this?
                {
                    fprintf( stdout, "Activation key might be invalid.\n" );
                }
                fprintf( stdout, "Serial number and activation key %smatch.\n",
                    memcmp( &key[15], sum, 2 ) ? "don't " : "" );
                key[12] = 0;
                fprintf( stdout, "Product code: %s\n", &key[9] );
            }
            return 0;
        default:
            fprintf( stderr, "Unsupported function.\n" );
            return 0;
    }
}
