#include <IndustryStandard/Acpi.h>
#include "Qemu.h"
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <IndustryStandard/LegacyVgaBios.h>
#include <Library/PciLib.h>
#include <Library/PrintLib.h>
#include <OvmfPlatforms.h>
#include "VbeShim.h"
