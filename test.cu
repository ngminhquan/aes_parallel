#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "AES.h"

int n = 1;
#define AES_BLOCKS pow(2, n)

void phex(uint8_t *str);
void test_ctr_parallel(void);

void phex(uint8_t *str)
{
    for (unsigned char i = 0; i < AES_BLOCKLEN; ++i)
        printf("%.2x ", str[i]);
    printf("\n");
}
// prints string as hex to file
void fphex(FILE *f, uint8_t *str)
{
    for (unsigned char i = 0; i < AES_BLOCKLEN; ++i)
        fprintf(f, "%.2x ", str[i]);
    fprintf(f, "\n");
}

// prints string as hex to file
void fwhex(FILE *f, uint8_t *str, size_t n)
{
    fwrite(str, AES_BLOCKLEN, n, f);
}

// prints string as hex to file
void frhex(FILE *f, uint8_t *str, size_t n)
{
    fread(str, AES_BLOCKLEN, n, f);
}

int main(void)
{
    printf("\n");
    test_ctr_parallel();
    return 0;
}

void test_ctr_parallel(void) {
    cudaDeviceProp iProp;
    int devNo = 0;
    cudaGetDeviceProperties(&iProp, devNo);
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t iv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    uint8_t *in = (uint8_t *)malloc(AES_BLOCKS * AES_BLOCKLEN * sizeof(uint8_t));
    FILE *fp = fopen("test.bin", "rb");
    frhex(fp, in, AES_BLOCKS);
    fclose(fp);

    struct AES_ctx ctx;
    AES_init_ctx_iv(sbox, &ctx, key, iv);

    printf("Speedup of CTR parallel: \n");
    printf("\n    |  %12e |bytes ", (double)(AES_BLOCKS * AES_BLOCKLEN));

    printf("\n    +---------------------------------------------------------------+ \n");
    AES_CTR_xcrypt_buffer_parallel(sbox, &ctx, in,  AES_BLOCKS*AES_BLOCKLEN);
    free(in);
}