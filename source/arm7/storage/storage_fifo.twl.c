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

static const uint8_t DSi_NAND_KEY_Y[16] = {
	0x76, 0xdc, 0xb9, 0x0a, 0xd3, 0xc4, 0x4d, 0xbd,
	0x1d, 0xdd, 0x2d, 0x20, 0x05, 0x00, 0xa0, 0xe1
};

static uint8_t nand_ctr_iv[16];


#define KEYSEED_DSI_NAND_0      0x24ee6906
#define KEYSEED_DSI_NAND_1      0xe65b601d
static void generate_key(aes_keyslot_t* keyslot, const uint32_t *console_id)
{
	vu32* key_x = (vu32*)keyslot->key_x;
	key_x[0] = console_id[0];
	key_x[1] = console_id[0] ^ KEYSEED_DSI_NAND_0;
	key_x[2] = console_id[1] ^ KEYSEED_DSI_NAND_1;
	key_x[3] = console_id[1];
	for(int i = 0; i < 16; ++i) {
		keyslot->key_y[i] = DSi_NAND_KEY_Y[i];
	}
}

static void set_ctr(uint8_t* ctr)
{
	for (int i = 0; i < 16; i++) REG_AES_IV[i] = ctr[i];
}

void dsi_crypt_init(const uint8_t *console_id, const uint8_t *emmc_cid)
{
	// generate_key(&AES_KEYSLOT3, (const uint32_t *)console_id);
	((volatile  uint32_t*)(AES_KEYSLOT3.key_y))[3] = 0xE1A00005;
	// REG_AES_CNT = ( AES_CNT_MODE(2) |
					// AES_WRFIFO_FLUSH |
					// AES_RDFIFO_FLUSH |
					// AES_CNT_KEY_APPLY |
					// AES_CNT_KEYSLOT(3) |
					// AES_CNT_DMA_WRITE_SIZE(0) |
					// AES_CNT_DMA_READ_SIZE(3)
					// );

	swiSHA1Calc(nand_ctr_iv, emmc_cid, 16);
}

// add two 128bit, little endian values and store the result into the first
static void u128_add(uint8_t *a, const uint8_t *b)
{
	uint8_t carry = 0;
	for (int i=0;i<16;i++)
	{
		uint16_t sum = a[i] + b[i] + carry;
		a[i] = sum & 0xff;
		carry = sum >> 8;
	}
}
// add two 128bit, little endian values and store the result into the first
static void u128_add32(uint8_t *a, const uint32_t b)
{
	uint8_t _b[16];
	memset(_b, 0, sizeof(_b));
	for (int i=0;i<4;i++)
		_b[i] = b >> (i*8);
	u128_add(a, _b);
}

static void setupAesRegs(uint32_t offset, unsigned count)
{
	REG_AES_CNT = ( AES_CNT_MODE(2) |
					AES_WRFIFO_FLUSH |
					AES_RDFIFO_FLUSH |
					AES_CNT_KEY_APPLY |
					AES_CNT_KEYSLOT(3) |
					AES_CNT_DMA_WRITE_SIZE(0) |
					AES_CNT_DMA_READ_SIZE(3)
					);

	uint8_t ctr[16];
	memcpy(ctr, nand_ctr_iv, sizeof(nand_ctr_iv));
	u128_add32(ctr, offset);
	set_ctr(ctr);
	REG_AES_BLKCNT = (count << 16);
	REG_AES_CNT |= 0x80000000;
}

extern void aaa(volatile void* dst, const volatile void* src, u32 blocklen, bool read);

static void cryptSectorsRead(volatile void* dst, const volatile void* src, u32 blocklen)
{
	volatile uint32_t* in32 = (volatile uint32_t*)src;
	for (unsigned i = 0; i < blocklen / 4; ++i)
	{
		while (((REG_AES_CNT) & 0x1F) == 16) {
			swiHalt();
		}
		REG_AES_WRFIFO = *in32;
	}
}


static void cryptSectorsWrite(volatile void* dst, const volatile void* src, u32 blocklen)
{
	volatile uint32_t* in32 = (volatile uint32_t*)src;
	for (unsigned i = 0; i < blocklen / 4; ++i)
	{
		while (((REG_AES_CNT) & 0x1F) == 16) {
			swiHalt();
		}
		REG_AES_WRFIFO = *in32++;
	}
}

void aaa(volatile void* dst, const volatile void* src, u32 blocklen, bool read)
{
	if(read)
		return cryptSectorsRead(dst, src, blocklen);
	else
		return cryptSectorsWrite(dst, src, blocklen);
}

#define SECTOR_SIZE              0x200
#define AES_BLOCK_SIZE          16
static u32 sdmmcReadSectors(const u8 devNum, u32 sect, u8 *buf, u32 count, bool crypt)
{
	u32 result;
	if(crypt)
	{
		NDMA_SRC(NDMA_CHANNEL) = (u32) &REG_AES_RDFIFO;
		NDMA_DEST(NDMA_CHANNEL) = (u32)buf;
		NDMA_BLENGTH(NDMA_CHANNEL) = 16;
		NDMA_BDELAY(NDMA_CHANNEL) = NDMA_BDELAY_DIV_1 | NDMA_BDELAY_CYCLES(0);
		NDMA_CR(NDMA_CHANNEL) = NDMA_ENABLE | NDMA_REPEAT | NDMA_BLOCK_SCALER(4)
								| NDMA_SRC_FIX | NDMA_DST_INC | NDMA_START_AES_OUT;
		// char buff[120];
		// sprintf(buff, "ARM7: reading %d sectors starting from: %d", count, sect);
		// nocashMessage(buff);
		setupAesRegs(sect * SECTOR_SIZE / AES_BLOCK_SIZE, count * SECTOR_SIZE / AES_BLOCK_SIZE);
		result = SDMMC_readSectorsCrypt(devNum, sect, buf, count);
		NDMA_CR(NDMA_CHANNEL) = 0;
	}
	else
#ifdef NDMA_CHANNEL
    if (!(((uintptr_t) buf) & 0x3))
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
		NDMA_SRC(NDMA_CHANNEL) = (u32) &REG_AES_RDFIFO;
		NDMA_DEST(NDMA_CHANNEL) = (u32) getTmioFifo(getTmioRegs(0));
		NDMA_BLENGTH(NDMA_CHANNEL) = 16;
		NDMA_BDELAY(NDMA_CHANNEL) = NDMA_BDELAY_DIV_1 | NDMA_BDELAY_CYCLES(0);
		NDMA_CR(NDMA_CHANNEL) = NDMA_ENABLE | NDMA_REPEAT | NDMA_BLOCK_SCALER(4)
								| NDMA_SRC_FIX | NDMA_DST_FIX | NDMA_START_AES_OUT;
		// char buff[120];
		// sprintf(buff, "ARM7: writing %d sectors starting from: %d", count, sect);
		// nocashMessage(buff);
		setupAesRegs(sect * SECTOR_SIZE / AES_BLOCK_SIZE, count * SECTOR_SIZE / AES_BLOCK_SIZE);
		result = SDMMC_writeSectorsCrypt(devNum, sect, buf, count);
		NDMA_CR(NDMA_CHANNEL) = 0;
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
