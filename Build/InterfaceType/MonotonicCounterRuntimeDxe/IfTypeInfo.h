#include <Uefi.h>
#include <Protocol/MonotonicCounter.h>
#include <Guid/MtcVendor.h>
#include <Library/BaseLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <PiDxe.h>
