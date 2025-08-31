#include <nds/disc_io.h>
#include <nds/arm9/sdmmc.h>
#include <nds/system.h>

bool nandfs_Startup(void)
{
    if (!nand_Startup() || !nand_SetupCrypt())
        return false;

    return true;
}

static bool nandfs_IsInserted(void)
{
    return true;
}

static bool nandfs_ClearStatus(void)
{
    return true;
}

static bool nandfs_Shutdown(void)
{
    return true;
}

static const DISC_INTERFACE __io_dsinand = {
    DEVICE_TYPE_DSI_NAND,
    FEATURE_MEDIUM_CANREAD | FEATURE_MEDIUM_CANWRITE,
    &nandfs_Startup,
    &nandfs_IsInserted,
    &nand_ReadSectorsCrypt,
    &nand_WriteSectorsCrypt,
    &nandfs_ClearStatus,
    &nandfs_Shutdown
};

const DISC_INTERFACE *get_io_dsinand(void)
{
    return isDSiMode() ? &__io_dsinand : NULL;
}
