#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Uefi.h>
#include <Protocol/Capsule.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/VariableLock.h>
#include <Guid/CapsuleVendor.h>
#include <Guid/AcpiS3Context.h>
#include <Library/PcdLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/FmpCapsule.h>
#include <Library/CapsuleLib.h>
#include <Library/PrintLib.h>
