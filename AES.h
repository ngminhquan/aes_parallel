#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#ifndef CTR
#define CTR 1
#endif
#define AES128 1
// Độ dài block AES
#define AES_BLOCKLEN 16
// Số cột trong ma trận trạng thái
#define Nb 4
// Số cột của ma trận khóa vòng
#define Nk 4
// Số vòng lặp
#define Nr 10
// Độ dài khóa AES
#define AES_KEYLEN 16
// Số byte mở rộng khóa
#define AES_keyExpSize 176
// Sbox
static const uint8_t sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// Hằng số vòng lặp phục vụ cho keyExpansion
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
// Định nghĩa kiểu dữ liệu cho ma trận trạng thái
typedef uint8_t state_t[4][4];
// Cấu trúc bao gồm khóa và vector khởi tạo (IV)
struct AES_ctx struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
  uint8_t Iv[AES_BLOCKLEN];
};
// Hàm khởi tạo AES với khóa
void AES_init_ctx(const uint8_t *sbox, struct AES_ctx *ctx, const uint8_t *key);
// Hàm khởi tạo AES với khóa và IV
void AES_init_ctx_iv(const uint8_t *sbox, struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv);
// Hàm thiết lập IV
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);
// Hàm mã hóa/Giải mã một buffer(Counter) sử dụng chế độ CTR
void AES_CTR_xcrypt_buffer(const uint8_t *sbox, struct AES_ctx *ctx, uint8_t *buf, size_t length);

// Hàm nhân trong trường GF(2^8)
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
#define multiply(x, y)                       \
  (((y & 1) * x) ^                           \
   ((y >> 1 & 1) * xtime(x)) ^               \
   ((y >> 2 & 1) * xtime(xtime(x))) ^        \
   ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ \
   ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))

// Hàm mở rộng khóa
void KeyExpansion(const uint8_t *sbox, uint8_t *RoundKey, const uint8_t *Key)
{
  unsigned i, j, k;
  uint8_t tempa[4];
  // Sao chép Nk từ khóa vào RoundKey
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }
  // Mở rộng khóa
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0] = RoundKey[k + 0];
      tempa[1] = RoundKey[k + 1];
      tempa[2] = RoundKey[k + 2];
      tempa[3] = RoundKey[k + 3];
    }

    if (i % Nk == 0)
    {

      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      {
        tempa[0] = sbox[tempa[0]];
        tempa[1] = sbox[tempa[1]];
        tempa[2] = sbox[tempa[2]];
        tempa[3] = sbox[tempa[3]];
      }

      tempa[0] = tempa[0] ^ Rcon[i / Nk];
    }
    j = i * 4;
    k = (i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

// Hàm AddRoundKey: XOR ma trận trạng thái với khóa vòng
__host__ __device__ void AddRoundKey(uint8_t round, state_t *state, const uint8_t *RoundKey)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// Hàm SubBytes: Thay thế mỗi byte trong ma trận trạng thái bằng giá trị từ S-box
__host__ __device__ void SubBytes(state_t *state, const uint8_t *sbox)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = sbox[(*state)[j][i]];
    }
  }
}

// Hàm ShiftRows: Dịch các hàng của ma trận trạng thái
__host__ __device__ void ShiftRows(state_t *state)
{
  uint8_t temp;

  temp = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

// Hàm MixColumns: Áp dụng phép trộn cột trong ma trận trạng thái
__host__ __device__ void MixColumns(state_t *state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
    Tm = (*state)[i][0] ^ (*state)[i][1];
    Tm = xtime(Tm);
    (*state)[i][0] ^= Tm ^ Tmp;
    Tm = (*state)[i][1] ^ (*state)[i][2];
    Tm = xtime(Tm);
    (*state)[i][1] ^= Tm ^ Tmp;
    Tm = (*state)[i][2] ^ (*state)[i][3];
    Tm = xtime(Tm);
    (*state)[i][2] ^= Tm ^ Tmp;
    Tm = (*state)[i][3] ^ t;
    Tm = xtime(Tm);
    (*state)[i][3] ^= Tm ^ Tmp;
  }
}

// Hàm Cipher: Thực hiện phép mã hoá AES trên ma trận trạng thái
__host__ __device__ void Cipher(const uint8_t *sbox, state_t *state, const uint8_t *RoundKey)
{
  uint8_t round = 0;

  AddRoundKey(0, state, RoundKey);

  for (round = 1;; ++round)
  {
    SubBytes(state, sbox);
    ShiftRows(state);
    if (round == Nr)
    {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }

  AddRoundKey(Nr, state, RoundKey);
}

// Hàm Kernel CTR: Thực hiện mã hoá CTR trên dữ liệu trong môi trường CUDA
__global__ void Cipher_Kernel_CTR(const uint8_t *sbox, const struct AES_ctx *ctx, uint8_t *buf, size_t AES_num_block)
{
  // Xác định chỉ số x của thread trong grid của GPU
  size_t x = threadIdx.x + (blockDim.x * blockIdx.x);

  // Đảm bảo thread chỉ thực hiện công việc nếu nó nằm trong phạm vi số block cần xử lý
  if (x < AES_num_block)
  {
    size_t i, remain;
    // Khởi tạo buffer với giá trị ban đầu là IV
    uint8_t buffer[AES_BLOCKLEN];
    memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
    //Thiết lập các giá trị counter
    for (remain = x, i = (AES_BLOCKLEN - 1); remain > 0 && i >= 0; remain /= 256, i--)
    {
      if ((short)buffer[i] + (short)(remain % 256) > 255 && i > 0)
        buffer[i - 1]++;
      buffer[i] += remain % 256;
    }
    // Thực hiện mã hoá AES trên block counter
    Cipher(sbox, (state_t *)buffer, ctx->RoundKey);
    // XOR với plaintext để tạo ciphertext
    for (i = 0; i < AES_BLOCKLEN; i++)
      buf[(x * AES_BLOCKLEN) + i] = (buf[(x * AES_BLOCKLEN) + i] ^ buffer[i]);
  }
}

void AES_init_ctx(const uint8_t *sbox, struct AES_ctx *ctx, const uint8_t *key)
{
  KeyExpansion(sbox, ctx->RoundKey, key);
}

void AES_init_ctx_iv(const uint8_t *sbox, struct AES_ctx *ctx, const uint8_t *key, const uint8_t *iv)
{
  KeyExpansion(sbox, ctx->RoundKey, key);
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv)
{
  memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}

// Hàm mã hoá AES-CTR trên một buf dữ liệu
void AES_CTR_xcrypt_buffer(const uint8_t *sbox, struct AES_ctx *ctx, uint8_t *buf, size_t length)
{
  uint8_t buffer[AES_BLOCKLEN];

  size_t i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    
    if (bi == AES_BLOCKLEN)
    {
      // Lấy giá trị mới của IV sau mỗi block và XOR với plaintext
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher(sbox, (state_t *)buffer, ctx->RoundKey);

      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
        if (ctx->Iv[bi] == 255)
        {
          ctx->Iv[bi] = 0;
          continue;
        }
        ctx->Iv[bi] += 1;
        break;
      }
      bi = 0;
    }
    // XOR với plaintext để tạo ciphertext
    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

// Hàm mã hoá AES-CTR đồng thời trên GPU
void AES_CTR_xcrypt_buffer_parallel(const uint8_t *sbox, struct AES_ctx *ctx, uint8_t *buf, size_t length)
{
  // Lấy thông số thiết bị GPU
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, 0);

  uint8_t *d_buf, *d_sbox;
  struct AES_ctx *d_ctx;

  // Cấp phát bộ nhớ trên GPU
  cudaMalloc((void **)&d_buf, sizeof(uint8_t) * length);
  cudaMalloc((void **)&d_ctx, sizeof(struct AES_ctx));
  cudaMalloc((void **)&d_sbox, sizeof(uint8_t) * 256);

  // Copy dữ liệu từ host sang GPU
  cudaMemcpy(d_buf, buf, sizeof(uint8_t) * length, cudaMemcpyHostToDevice);
  cudaMemcpy(d_ctx, ctx, sizeof(struct AES_ctx), cudaMemcpyHostToDevice);
  cudaMemcpy(d_sbox, sbox, sizeof(uint8_t) * 256, cudaMemcpyHostToDevice);

  // Tính toán số block và thread cần thiết
  size_t AES_num_block = length / AES_BLOCKLEN;
  size_t threadPerBlock = min(AES_num_block, (size_t)prop.maxThreadsPerBlock);
  //size_t threadPerBlock = 512;
  size_t blockNumber = (AES_num_block + threadPerBlock - 1) / threadPerBlock;
  printf("AES number of blocks: %ld\n", AES_num_block);
  printf("thread per block: %ld\n", threadPerBlock);
  printf("block number: %ld\n", blockNumber);
  // Thực hiện mã hoá AES-CTR trên GPU
  Cipher_Kernel_CTR<<<blockNumber, threadPerBlock>>>(d_sbox, d_ctx, d_buf, AES_num_block);
  // Đồng bộ hoá thiết bị GPU
  cudaDeviceSynchronize();
  // Copy dữ liệu từ GPU về host
  cudaMemcpy(buf, d_buf, sizeof(uint8_t) * length, cudaMemcpyDeviceToHost);
  // Giải phóng bộ nhớ trên GPU
  cudaFree(d_buf);
  cudaFree(d_ctx);
  cudaFree(d_sbox);
}


#endif