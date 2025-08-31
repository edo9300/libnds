// SPDX-License-Identifier: Zlib
//
// Copyright (C) 2023 Antonio Niño Díaz

#include <stddef.h>

#include <nds.h>
#include <nds/ndma.h>
#include <nds/fifocommon.h>
#include <nds/fifomessages.h>
#include <string.h>
#include <nds/debug.h>
#include <stdio.h>

#define NDMA_CHANNEL 1

static uint8_t nand_ctr_iv[16];

#define KEYSEED_DSI_NAND_0      0x24ee6906
#define KEYSEED_DSI_NAND_1      0xe65b601d
static void generate_key(aes_keyslot_t* keyslot, const uint32_t *console_id)
{
	// FIXME: 3ds uses a different permutation of the console id
	vu32* key_x = (vu32*)keyslot->key_x;
	key_x[0] = console_id[0];
	key_x[1] = console_id[0] ^ KEYSEED_DSI_NAND_0;
	key_x[2] = console_id[1] ^ KEYSEED_DSI_NAND_1;
	key_x[3] = console_id[1];
	// "Activate" the key Y to generate the normal key
	((volatile  uint32_t*)(keyslot->key_y))[3] = 0xE1A00005;
}

void dsi_crypt_init(const uint8_t *console_id, const uint8_t *emmc_cid)
{
	// "Complete" the key Y in the aes engine so that the Normal Key for
	// NAND decryption is derived in the Keyslot 3
	generate_key(&AES_KEYSLOT3, (const uint32_t *)console_id);
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
	u8 sha1Digest[20];
	swiSHA1Calc(sha1Digest, emmc_cid, 16);
	memcpy(nand_ctr_iv, sha1Digest, 16);
}

// add a 32bit int to a 128bit little endian value
static void u128_add32(const uint8_t *a, uint32_t b, volatile uint8_t *dest)
{
	uint8_t carry = 0;
	for (int i = 0; i < 16; i++)
	{
		uint16_t sum = a[i] + (b & 0xff) + carry;
		dest[i] = sum & 0xff;
		carry = sum >> 8;
		b >>= 8;
	}
}

#define SECTOR_SIZE              0x200
#define AES_BLOCK_SIZE          16
static void setupAesRegs(uint32_t sectorNum, unsigned totalSectors)
{
	REG_AES_CNT = ( AES_CNT_MODE(2) |
					AES_WRFIFO_FLUSH |
					AES_RDFIFO_FLUSH |
					AES_CNT_KEY_APPLY | AES_CNT_KEYSLOT(3) | // apply keyslot 3 containing the nand normal key
					AES_CNT_DMA_WRITE_SIZE(0) | AES_CNT_DMA_READ_SIZE(3) // set both input and output expected dma size to 16 words
					);
	// The blkcnt register holds the number of total blocks (16 bytes) to be parsed
	// by the current aes operation
	uint32_t aesBlockCount = totalSectors * (SECTOR_SIZE / AES_BLOCK_SIZE);
	// FIXME: handle transfers greater than 0xFFFF blocks (0xFFFF0 bytes, which translate to 2047 sectors)
	REG_AES_BLKCNT = (aesBlockCount << 16);

	uint32_t offset = sectorNum * (SECTOR_SIZE / AES_BLOCK_SIZE);
	// The ctr is the base ctr calculated by the sha of the CID + (address / 16)
	// the aes engine will take care of incrementing it automatically
	u128_add32(nand_ctr_iv, offset, REG_AES_IV);

	REG_AES_CNT |= AES_CNT_ENABLE;
}

extern void aaa(volatile void* dst, const volatile void* src, u32 numSectors, bool read);

static void cryptSectorsRead(volatile void* dst, const volatile void* inSdmcFifo, u32 numSectors)
{
	const bool word_aligned = !(((uintptr_t) dst) & 0x3);
	volatile uint32_t* inSdmcFifo32 = (volatile uint32_t*)inSdmcFifo;
	if(word_aligned)
#ifdef NDMA_CHANNEL
	{
		for (unsigned i = 0; i < numSectors / 4; ++i)
		{
			while (((REG_AES_CNT) & 0x1F) == 16);
			REG_AES_WRFIFO = *inSdmcFifo32;
		}
	}
#else
	{
		volatile uint32_t* out32 = (volatile uint32_t*)dst;
		for (unsigned i = 0; i < numSectors / (4 * 16); ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				REG_AES_WRFIFO = *inSdmcFifo32;
			}
			while (((REG_AES_CNT >> 0x5) & 0x1F) < 16);
			for (int j = 0; j < 16; ++j)
			{
				*out32++ = REG_AES_RDFIFO;
			}
		}
	}
#endif
	else
	{
		volatile uint8_t* out8 = (volatile uint8_t*)dst;
		for (unsigned i = 0; i < numSectors / (4 * 16); ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				REG_AES_WRFIFO = *inSdmcFifo32;
			}
			while (((REG_AES_CNT >> 0x5) & 0x1F) < 16);
			for (int j = 0; j < 16; ++j)
			{
				const uint32_t tmp = REG_AES_RDFIFO;
				*out8++ = tmp;
				*out8++ = tmp >> 8;
				*out8++ = tmp >> 16;
				*out8++ = tmp >> 24;
			}
		}
	}
}


static void cryptSectorsWrite(volatile void* outSdmcFifo, const volatile void* src, u32 numSectors)
{
#ifdef NDMA_CHANNEL
	(void)outSdmcFifo;
	if (!(((uintptr_t) src) & 0x3))
	{
		volatile uint32_t* in32 = (volatile uint32_t*)src;
		for (unsigned i = 0; i < numSectors / 4; ++i)
		{
			while (((REG_AES_CNT) & 0x1F) == 16);
			REG_AES_WRFIFO = *in32++;
		}
	}
	else
	{
		volatile uint8_t* in8 = (volatile uint8_t*)src;
		for (unsigned i = 0; i < numSectors / 4; ++i)
		{
			uint32_t tmp = *in8++;
			tmp |= *in8++ << 8;
			tmp |= *in8++ << 16;
			tmp |= *in8++ << 24;
			while (((REG_AES_CNT) & 0x1F) == 16);
			REG_AES_WRFIFO = tmp;
		}
	}
#else
	volatile uint32_t* outSdmcFifo32 = (volatile uint32_t*)outSdmcFifo;
	if (!(((uintptr_t) src) & 0x3))
	{
		volatile uint32_t* in32 = (volatile uint32_t*)src;
		for (unsigned i = 0; i < numSectors / (4 * 16); ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				REG_AES_WRFIFO = *in32++;
			}
			while (((REG_AES_CNT >> 0x5) & 0x1F) < 16);
			for (int j = 0; j < 16; ++j)
			{
				*outSdmcFifo32 = REG_AES_RDFIFO;
			}
		}
	}
	else
	{
		volatile uint8_t* in8 = (volatile uint8_t*)src;
		for (unsigned i = 0; i < numSectors / (4 * 16); ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				uint32_t tmp = *in8++;
				tmp |= *in8++ << 8;
				tmp |= *in8++ << 16;
				tmp |= *in8++ << 24;
				REG_AES_WRFIFO = tmp;
			}
			while (((REG_AES_CNT >> 0x5) & 0x1F) < 16);
			for (int j = 0; j < 16; ++j)
			{
				*outSdmcFifo32 = REG_AES_RDFIFO;
			}
		}
	}
#endif
}

void aaa(volatile void* dst, const volatile void* src, u32 numSectors, bool read)
{
	if(read)
		return cryptSectorsRead(dst, src, numSectors);
	else
		return cryptSectorsWrite(dst, src, numSectors);
}

static u32 sdmmcReadSectors(const u8 devNum, u32 sect, u8 *buf, u32 count, bool crypt)
{
	u32 result;
	const bool word_aligned = !(((uintptr_t) buf) & 0x3);
	if(crypt)
	{
#ifdef NDMA_CHANNEL
		if(word_aligned)
		{
			NDMA_SRC(NDMA_CHANNEL) = (u32) &REG_AES_RDFIFO;
			NDMA_DEST(NDMA_CHANNEL) = (u32)buf;
			NDMA_BLENGTH(NDMA_CHANNEL) = 16;
			NDMA_BDELAY(NDMA_CHANNEL) = NDMA_BDELAY_DIV_1 | NDMA_BDELAY_CYCLES(0);
			NDMA_CR(NDMA_CHANNEL) = NDMA_ENABLE | NDMA_REPEAT | NDMA_BLOCK_SCALER(4)
									| NDMA_SRC_FIX | NDMA_DST_INC | NDMA_START_AES_OUT;
		}
#endif
		setupAesRegs(sect, count);
		result = SDMMC_readSectorsCrypt(devNum, sect, buf, count);
#ifdef NDMA_CHANNEL
		if(word_aligned)
		{
			NDMA_CR(NDMA_CHANNEL) = 0;
		}
#endif
	}
	else
#ifdef NDMA_CHANNEL
    if (word_aligned)
    {
		NDMA_SRC(NDMA_CHANNEL) = (u32) getTmioFifo(getTmioRegs(0));
		NDMA_DEST(NDMA_CHANNEL) = (u32)buf;
		NDMA_BLENGTH(NDMA_CHANNEL) = 512 / 4;
		NDMA_BDELAY(NDMA_CHANNEL) = NDMA_BDELAY_DIV_1 | NDMA_BDELAY_CYCLES(0);
		NDMA_CR(NDMA_CHANNEL) = NDMA_ENABLE | NDMA_REPEAT | NDMA_BLOCK_SCALER(4)
								| NDMA_SRC_FIX | NDMA_DST_INC | NDMA_START_SDMMC;
		result = SDMMC_readSectors(devNum, sect, NULL, count);
		NDMA_CR(NDMA_CHANNEL) = 0;
    }
    else
#endif
    {
        result = SDMMC_readSectors(devNum, sect, buf, count);
    }
	return result;
}

static u32 sdmmcWriteSectors(const u8 devNum, u32 sect, const u8 *buf, u32 count, bool crypt)
{
	u32 result;
	if(crypt)
	{
#ifdef NDMA_CHANNEL
		NDMA_SRC(NDMA_CHANNEL) = (u32) &REG_AES_RDFIFO;
		NDMA_DEST(NDMA_CHANNEL) = (u32) getTmioFifo(getTmioRegs(0));
		NDMA_BLENGTH(NDMA_CHANNEL) = 16;
		NDMA_BDELAY(NDMA_CHANNEL) = NDMA_BDELAY_DIV_1 | NDMA_BDELAY_CYCLES(0);
		NDMA_CR(NDMA_CHANNEL) = NDMA_ENABLE | NDMA_REPEAT | NDMA_BLOCK_SCALER(4)
								| NDMA_SRC_FIX | NDMA_DST_FIX | NDMA_START_AES_OUT;
#endif
		setupAesRegs(sect, count);
		result = SDMMC_writeSectorsCrypt(devNum, sect, buf, count);
#ifdef NDMA_CHANNEL
		NDMA_CR(NDMA_CHANNEL) = 0;
#endif
	}
	else
#ifdef NDMA_CHANNEL
    if (!(((uintptr_t) buf) & 0x3))
    {
        NDMA_SRC(NDMA_CHANNEL) = (u32) buf;
        NDMA_DEST(NDMA_CHANNEL) = (u32) getTmioFifo(getTmioRegs(0));
        NDMA_BLENGTH(NDMA_CHANNEL) = 512 / 4;
        NDMA_BDELAY(NDMA_CHANNEL) = NDMA_BDELAY_DIV_1 | NDMA_BDELAY_CYCLES(0);
        NDMA_CR(NDMA_CHANNEL) = NDMA_ENABLE | NDMA_REPEAT | NDMA_BLOCK_SCALER(4)
                                | NDMA_SRC_INC | NDMA_DST_FIX | NDMA_START_SDMMC;
        result = SDMMC_writeSectors(devNum, sect, NULL, count);
        NDMA_CR(NDMA_CHANNEL) = 0;
    }
    else
#endif
    {
        result = SDMMC_writeSectors(devNum, sect, buf, count);
    }
	return result;
}

int sdmmcMsgHandler(int bytes, void *user_data, FifoMessage *msg)
{
    (void)bytes;
    (void)user_data;

    int retval = 0;

    switch (msg->type)
    {
        case SDMMC_SD_READ_SECTORS:
            retval = sdmmcReadSectors(SDMMC_DEV_CARD, msg->sdParams.startsector,
                                      msg->sdParams.buffer, msg->sdParams.numsectors, false);
            break;
        case SDMMC_SD_WRITE_SECTORS:
            retval = sdmmcWriteSectors(SDMMC_DEV_CARD, msg->sdParams.startsector,
                                       msg->sdParams.buffer, msg->sdParams.numsectors, false);
            break;
        case SDMMC_NAND_READ_SECTORS:
            retval = sdmmcReadSectors(SDMMC_DEV_eMMC, msg->sdParams.startsector,
                                      msg->sdParams.buffer, msg->sdParams.numsectors, false);
            break;
        case SDMMC_NAND_WRITE_SECTORS:
            retval = sdmmcWriteSectors(SDMMC_DEV_eMMC, msg->sdParams.startsector,
                                       msg->sdParams.buffer, msg->sdParams.numsectors, false);
            break;
        case SDMMC_NAND_READ_ENCRYPTED_SECTORS:
            retval = sdmmcReadSectors(SDMMC_DEV_eMMC, msg->sdParams.startsector,
                                      msg->sdParams.buffer, msg->sdParams.numsectors, true);
            break;
        case SDMMC_NAND_WRITE_ENCRYPTED_SECTORS:
            retval = sdmmcWriteSectors(SDMMC_DEV_eMMC, msg->sdParams.startsector,
                                       msg->sdParams.buffer, msg->sdParams.numsectors, true);
            break;
    }

    return retval;
}

int sdmmcValueHandler(u32 value, void *user_data)
{
    (void)user_data;

    int result = 0;

    switch (value)
    {
        case SDMMC_SD_STATUS:
            result = SDMMC_getDiskStatus(SDMMC_DEV_CARD);
            break;

        case SDMMC_NAND_STATUS:
            result = SDMMC_getDiskStatus(SDMMC_DEV_eMMC);
            break;

        case SDMMC_SD_START:
            result = SDMMC_init(SDMMC_DEV_CARD);
            break;

        case SDMMC_NAND_START:
            result = SDMMC_init(SDMMC_DEV_eMMC);
            break;

        case SDMMC_SD_STOP:
            result = SDMMC_deinit(SDMMC_DEV_CARD);
            break;

        case SDMMC_NAND_STOP:
            break;

        case SDMMC_SD_SIZE:
            result = SDMMC_getSectors(SDMMC_DEV_CARD);
            break;

        case SDMMC_NAND_SIZE:
            result = SDMMC_getSectors(SDMMC_DEV_eMMC);
            break;
    }

    return result;
}
