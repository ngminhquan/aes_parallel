#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h> 
#include "AES.h"

#define AES_BLOCKS pow(2,24)

void phex(uint8_t* str);

int test_encrypt_ctr(void);
int test_decrypt_ctr(void);
int test_parallel_ctr(void);

void test_performance_ctr_parallel(void);

int main(void)
{
    int exit;

#if defined(AES128)
    printf("\nTesting AES128\n\n");
#else
    printf("You need to specify AES128. Exiting");
    return 0;
#endif
    exit = test_encrypt_ctr() + test_decrypt_ctr() + test_parallel_ctr();
    printf("\n");
    test_performance_ctr_parallel();
    return exit;
}

void phex(uint8_t* str)
{
    for (unsigned char i = 0; i < AES_BLOCKLEN; ++i)
        printf("%.2x ", str[i]);
    printf("\n");
}
// prints string as hex to file
void fphex(FILE *f, uint8_t* str)
{
    for (unsigned char i = 0; i < AES_BLOCKLEN; ++i)
        fprintf(f, "%.2x ", str[i]);
    fprintf(f, "\n");
}

// prints string as hex to file
void fwhex(FILE *f, uint8_t* str, size_t n)
{
    fwrite(str, AES_BLOCKLEN, n, f);
}

// prints string as hex to file
void frhex(FILE *f, uint8_t* str, size_t n)
{
    fread(str, AES_BLOCKLEN, n, f);
}

int test_xcrypt_ctr(const char* xcrypt);

int test_encrypt_ctr(void)
{
    return test_xcrypt_ctr("encrypt");
}

int test_decrypt_ctr(void)
{
    return test_xcrypt_ctr("decrypt");
}

int test_xcrypt_ctr(const char* xcrypt)
{

#if defined(AES128)
    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t in[64]  = { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
                        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
                        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee };
#endif
    uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    uint8_t out[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;
    
    AES_init_ctx_iv(sbox, &ctx, key, iv);
    AES_CTR_xcrypt_buffer(sbox, &ctx, in, 64);
  
    printf("CTR %s: ", xcrypt);
  
    if (0 == memcmp((char *) out, (char *) in, 64)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

int test_parallel_ctr(void)
{

#if defined(AES128)
    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t in[64]  = { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
                        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
                        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee };
#endif
    uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    uint8_t out[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t in_old[64];
    memcpy(in_old, in, 64);
    struct AES_ctx ctx;
    
    AES_init_ctx_iv(sbox, &ctx, key, iv);
    AES_CTR_xcrypt_buffer_parallel(sbox, &ctx, in, 64);
  
    printf("CTR parallel: ");
  
    if (0 == memcmp((char *) out, (char *) in, 64)) {
      AES_CTR_xcrypt_buffer_parallel(sbox, &ctx, in, 64);
      if (0 == memcmp((char *) in_old, (char *) in, 64)) {
          printf("SUCCESS!\n");
    return(0);
      } else {
          printf("FAILURE!\n");
    return(1);
      }
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

void first_try(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length);

void test_performance_ctr_parallel(void){
    struct timeval start, end;
    double time1, time2;
    size_t i;
#if defined(AES128)
    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif
    uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    uint8_t* in = (uint8_t*)malloc(AES_BLOCKS * AES_BLOCKLEN * sizeof(uint8_t));
    FILE *fp = fopen("test.bin", "rb");
    frhex(fp, in, AES_BLOCKS);
    fclose(fp);

    struct AES_ctx ctx;
    AES_init_ctx_iv(sbox, &ctx, key, iv);
    first_try(sbox, &ctx, in, 64);

    printf("Speedup of CTR parallel: \n");

		printf("\n    +---------------------------------------------------------------+ ");
		printf("\n    |  %12s |  %12s |  %12s |  %12s |", "File Size", "Serial", "Parallel", "Speed Up");
		printf("\n    +---------------------------------------------------------------+ ");
    for(i = pow(2,4); i <= AES_BLOCKS; i *= 2)
    {
        //if(i < pow(2, 10))
        //{
            int times;
            gettimeofday( &start, NULL );
            for(times = 0; times < 3; times++)
            {
                AES_CTR_xcrypt_buffer(sbox, &ctx, in, i * AES_BLOCKLEN);
                AES_CTR_xcrypt_buffer(sbox, &ctx, in, i * AES_BLOCKLEN);
            }
            gettimeofday( &end, NULL );
            time1 = (1000000 * ( end.tv_sec - start.tv_sec ) + (end.tv_usec - start.tv_usec)) / 3;

        //    gettimeofday( &start, NULL );
        //    for(times = 0; times < 3; times++)
        //    {
        //        AES_ECB_encrypt_buffer_parallel(sbox, &ctx, in, i * AES_BLOCKLEN);
        //        AES_ECB_decrypt_buffer_parallel(rsbox, &ctx, in, i * AES_BLOCKLEN);
        //    }
        //    gettimeofday( &end, NULL );
        //    time2 = (1000000 * ( end.tv_sec - start.tv_sec ) + (end.tv_usec - start.tv_usec)) / 3;
        //}
        //else
        //{
        //    gettimeofday( &start, NULL );
        //    AES_ECB_encrypt_buffer(sbox, &ctx, in, i * AES_BLOCKLEN);
        //    AES_ECB_decrypt_buffer(rsbox, &ctx, in, i * AES_BLOCKLEN);
        //    gettimeofday( &end, NULL );
        //    time1 = (1000000 * ( end.tv_sec - start.tv_sec ) + (end.tv_usec - start.tv_usec));

            gettimeofday( &start, NULL );
            AES_CTR_xcrypt_buffer_parallel(sbox, &ctx, in, i * AES_BLOCKLEN);
            AES_CTR_xcrypt_buffer_parallel(sbox, &ctx, in, i * AES_BLOCKLEN);
            gettimeofday( &end, NULL );
            time2 = (1000000 * ( end.tv_sec - start.tv_sec ) + (end.tv_usec - start.tv_usec));
        //}
        printf("\n    |  %12e |  %12.3lf |  %12.3lf |  %12.3lf |", (double)(i * AES_BLOCKLEN), time1 / (double) 1000, time2 / (double) 1000, time1 / time2);
    }
		printf("\n    +---------------------------------------------------------------+ \n\n");
    free(in);
}


void first_try(const uint8_t* sbox, const struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
	cudaDeviceProp prop;	
	cudaGetDeviceProperties(&prop, 0);	

  uint8_t *d_buf, *d_sbox;
  struct AES_ctx* d_ctx;
 
  cudaMalloc((void**)&d_buf, sizeof(uint8_t) * length);
  cudaMalloc((void**)&d_ctx, sizeof(struct AES_ctx));
  cudaMalloc((void**)&d_sbox, sizeof(uint8_t) * 256);
 
  cudaMemcpy(d_buf, buf, sizeof(uint8_t) * length, cudaMemcpyHostToDevice);
  cudaMemcpy(d_ctx, ctx, sizeof(struct AES_ctx), cudaMemcpyHostToDevice);
  cudaMemcpy(d_sbox, sbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);

  size_t stride = 1;
  size_t AES_num_block = length / AES_BLOCKLEN;
  size_t threadPerBlock = min((AES_num_block + stride - 1) / stride, (size_t)prop.maxThreadsPerBlock);
  size_t blockNumber = (((AES_num_block + stride - 1) / stride) + threadPerBlock - 1) / threadPerBlock;
  Cipher_Kernel_CTR<<<blockNumber, threadPerBlock>>> (d_sbox, d_ctx, d_buf, AES_num_block);
  
  cudaMemcpy(buf, d_buf, sizeof(uint8_t) * length, cudaMemcpyDeviceToHost);
  
  cudaFree(d_buf);
  cudaFree(d_ctx);
  cudaFree(d_sbox);
}
