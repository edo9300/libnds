#include <stdbool.h>
#include <string.h>

#include <nds.h>

static u8 nand_ctr_iv[16] = {0};
static const u8 empty[16] = {0};

#define KEYSEED_DSI_NAND_0      0x24ee6906
#define KEYSEED_DSI_NAND_1      0xe65b601d

// "Complete" the keys in the aes engine so that the Normal Key for
// NAND decryption is derived in the Keyslot 3
static void generate_key(aes_keyslot_t* keyslot, u64 console_id)
{
    vu32* key_x = (vu32*)keyslot->key_x;
    u32 lower = (u32)(console_id & 0xFFFFFFFF);
    u32 upper = (u32)(console_id >> 32);
    key_x[0] = lower;
    // this bit is only set on 3ds consoles
    const bool is3ds = (lower & 0x80000000) != 0;
    if(is3ds)
    {
        static const char NINTENDO[] = {'N','I','N','T','E','N','D','O'};
        key_x[1] = ((vu32*)NINTENDO)[0];
        key_x[2] = ((vu32*)NINTENDO)[1];
    }
    else
    {
        key_x[1] = lower ^ KEYSEED_DSI_NAND_0;
        key_x[2] = upper ^ KEYSEED_DSI_NAND_1;
    }
    key_x[3] = upper;
    // "Activate" the key Y to generate the normal key
    ((volatile  u32*)(keyslot->key_y))[3] = 0xE1A00005;
}

void nandCrypt_Init(void)
{
    if (memcmp(empty, nand_ctr_iv, 16) != 0)
        return;

    generate_key(&AES_KEYSLOT3, getConsoleID());
    REG_AES_CNT = ( AES_CNT_MODE(2) |
                    AES_WRFIFO_FLUSH |
                    AES_RDFIFO_FLUSH |
                    AES_CNT_KEY_APPLY |
                    AES_CNT_KEYSLOT(3) |
                    AES_CNT_DMA_WRITE_SIZE(0) |
                    AES_CNT_DMA_READ_SIZE(3)
                    );

    // Calculate the Input Vector used for NAND decryption
    // First 16 bytes of the SHA of the nand cid will be used
    // as base for the input vector
    u8 CID[16];
    SDMMC_getCidRaw(SDMMC_DEV_eMMC, (u32*)CID);
    for (int i = 0; i < 16; ++i)
    {
        REG_CID[i] = CID[i];
    }
    u8 sha1Digest[20];
    swiSHA1Calc(sha1Digest, CID, 16);
    memcpy(nand_ctr_iv, sha1Digest, 16);
}

// add a 32bit int to a 128bit little endian value
static void u128_add32(const u8 *a, u32 b, vu8 *dest)
{
    u8 carry = 0;
    for (int i = 0; i < 16; i++)
    {
        u16 sum = a[i] + (b & 0xff) + carry;
        dest[i] = sum & 0xff;
        carry = sum >> 8;
        b >>= 8;
    }
}

void nandCrypt_SetIV(u32 offset)
{
    u128_add32(nand_ctr_iv, offset, REG_AES_IV);
}
