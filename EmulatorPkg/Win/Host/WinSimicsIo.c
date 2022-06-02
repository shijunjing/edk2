/**@file
Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "WinSimicsIo.h"



static conf_object_t *sim_obj;

//copy from simics-base\core\src\core\common\fatal.c
#ifdef _WIN32
static DWORD simics_main_thread_id;
#else
static pthread_t simics_main_thread;
#endif

void
set_main_thread(void)
{
#ifdef _WIN32
        simics_main_thread_id = GetCurrentThreadId();
#else
        simics_main_thread = pthread_self();
#endif
}

bool
in_simics_main_thread(void)
{
#ifdef _WIN32
        return GetCurrentThreadId() == simics_main_thread_id;
#else
        return pthread_equal(pthread_self(), simics_main_thread);
#endif
}


static void
print_attribute(attr_value_t val)
{
        if (SIM_attr_is_invalid(val)) {
                // be quiet

        } else if (SIM_attr_is_integer(val)) {
                printf("0x%llx", SIM_attr_integer(val));

        } else if (SIM_attr_is_string(val)) {
                printf("%s", SIM_attr_string(val));

        } else if (SIM_attr_is_object(val)) {
                printf("%s", SIM_object_name(SIM_attr_object(val)));

        } else if (SIM_attr_is_boolean(val)) {
                printf("%s", SIM_attr_boolean(val) ? "True" : "False");

        } else if (SIM_attr_is_floating(val)) {
                printf("%g", SIM_attr_floating(val));

        } else if (SIM_attr_is_nil(val)) {
                printf("NIL");

        } else if (SIM_attr_is_list(val)) {
                printf("[");
                int first = 1;
                for (unsigned i = 0; i < SIM_attr_list_size(val); i++) {
                        if (!first) printf(", ");
                        first = 0;
                        print_attribute(SIM_attr_list_item(val, i));
                }
                printf("]");

        } else if (SIM_attr_is_dict(val)) {
                printf("{");
                int first = 1;
                for (unsigned i = 0; i < SIM_attr_dict_size(val); i++) {
                        if (!first) printf(", ");
                        first = 0;
                        print_attribute(SIM_attr_dict_key(val, i));
                        printf(" : ");
                        print_attribute(SIM_attr_dict_value(val, i));
                }
                printf("}");

        } else if (SIM_attr_is_data(val)) {
                printf("<data attribute>");
        } else {
                printf("<unknown attribute>");
        }
}


conf_object_t *mem_obj;
conf_object_t *dma_obj;

conf_object_t *go_to_host_dev;
typedef struct {
        /* Simics configuration object */
        conf_object_t obj;

        // Size of allocation attribute
        uint64 allocation_size;

        uint64  dummy_return_value;
} go_to_host_device_t;

//SIMICS_IO_PPI mSimicsIoPpi;
SIMICS_IO_PRIVATE     mSimicsIoPrivate;
SIMICS_IO_PPI         *SimicsIoPpiPtr;

EFI_STATUS
EFIAPI
CreateSimicsCliCmd (
  IN      CHAR8   *CmdBuffer,
  IN OUT  UINTN   *CmdBufferLen,
  IN      CHAR8   *Format,
  ...
  )
{
  VA_LIST                   Marker;
  UINTN                     CharCount;
  CHAR8                     Buffer[0x1000];
  //EFI_STATUS                Status;

  ZeroMem(Buffer, sizeof(Buffer));
  //
  // Convert message to ASCII String and print out
  //
  VA_START (Marker, Format);
  AsciiVSPrint (Buffer, sizeof(Buffer), Format, Marker);
  VA_END (Marker);
  CharCount = AsciiStrLen(Buffer);
  ASSERT(CharCount < 0x1000);

  if (*CmdBufferLen < CharCount){
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem(CmdBuffer, Buffer, CharCount);
  *CmdBufferLen = CharCount;
  return EFI_SUCCESS;
}



EFI_STATUS
EFIAPI
SimicsIoBankRead (
  IN     SIMICS_IO_PPI    *This,
  IN     CHAR8            *BankName,
  IN     UINTN            Offset,
  IN     UINTN            Size,
  IN     UINTN            Count,
  OUT    VOID             *Buffer
  )
{
  CHAR8              Cmd[0x50];
  UINTN              CmdLen;
  attr_value_t       ret;

  ZeroMem(Cmd, sizeof(Cmd));
  CmdLen = sizeof(Cmd);
  CreateSimicsCliCmd(Cmd, &CmdLen, "read-device-offset %a.%a %d %d", This->CliDevName, BankName, Offset, Size);
  printf("CmdLen=%llu\n", CmdLen);
  printf("Cmd=%s\n", Cmd);
  ret = SIM_run_command(Cmd);
  if (SIM_clear_exception()) {
          printf("Got exception: %s\n", SIM_last_error());
  } else {
          printf("Cmd (%s) return value: ", Cmd);
          print_attribute(ret);
          SIM_attr_free(&ret);
          printf("\n");
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoBankWrite (
  IN     SIMICS_IO_PPI    *This,
  IN     CHAR8            *BankName,
  IN     UINTN            Offset,
  IN     UINTN            Size,
  IN     UINTN            Count,
  IN     VOID             *Buffer
  )
{
  CHAR8              Cmd[0x100];
  UINTN              CmdLen;
  attr_value_t       ret;

  ZeroMem(Cmd, sizeof(Cmd));
  CmdLen = sizeof(Cmd);
  CreateSimicsCliCmd(
    Cmd,
    &CmdLen,
    "write-device-offset bank = %a.bank.%a offset = %d size = %d data = 0x%x -b", This->CliDevName, BankName, Offset, Size, *(UINT32 *)Buffer
    );
  printf("CmdLen=%llu\n", CmdLen);
  printf("Cmd=%s\n", Cmd);
  ret = SIM_run_command(Cmd);
  if (SIM_clear_exception()) {
          printf("Got exception: %s\n", SIM_last_error());
  } else {
          printf("Cmd (%s) return value: ", Cmd);
          print_attribute(ret);
          SIM_attr_free(&ret);
          printf("\n");
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoRegRead (
  IN     SIMICS_IO_PPI    *This,
  IN     CHAR8            *RegName,
  IN     UINTN            Count,
  OUT    VOID             *Buffer
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
SimicsIoRegWrite (
  IN     SIMICS_IO_PPI    *This,
  IN     CHAR8            *RegName,
  IN     UINTN            Count,
  IN     VOID             *Buffer
  )
{
  return EFI_UNSUPPORTED;
}


EFI_STATUS
EFIAPI
SimicsIoPollMem (
  IN  SIMICS_IO_PPI                            *This,
  IN  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH    Width,
  IN  UINT64                                   Address,
  IN  UINT64                                   Mask,
  IN  UINT64                                   Value,
  IN  UINT64                                   Delay,
  OUT UINT64                                   *Result
  )
{
  return EFI_UNSUPPORTED;
}


EFI_STATUS
EFIAPI
SimicsIoPollIo (
  IN  SIMICS_IO_PPI                          *This,
  IN  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH  Width,
  IN  UINT64                                 Address,
  IN  UINT64                                 Mask,
  IN  UINT64                                 Value,
  IN  UINT64                                 Delay,
  OUT UINT64                                 *Result
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
SimicsIoMemRead (
  IN     SIMICS_IO_PPI                          *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH  Width,
  IN     UINT64                                 Address,
  IN     UINTN                                  Count,
  OUT    VOID                                   *Buffer
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
SimicsIoMemWrite (
  IN     SIMICS_IO_PPI        *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH  Width,
  IN     UINT64                                 Address,
  IN     UINTN                                  Count,
  IN     VOID                                   *Buffer
  )
{
  return EFI_UNSUPPORTED;
}

#define MAX_IO_PORT_ADDRESS   0xFFFF

//
// Lookup table for increment values based on transfer widths
//
UINT8 mInStride[] = {
  1, // EfiCpuIoWidthUint8
  2, // EfiCpuIoWidthUint16
  4, // EfiCpuIoWidthUint32
  8, // EfiCpuIoWidthUint64
  0, // EfiCpuIoWidthFifoUint8
  0, // EfiCpuIoWidthFifoUint16
  0, // EfiCpuIoWidthFifoUint32
  0, // EfiCpuIoWidthFifoUint64
  1, // EfiCpuIoWidthFillUint8
  2, // EfiCpuIoWidthFillUint16
  4, // EfiCpuIoWidthFillUint32
  8  // EfiCpuIoWidthFillUint64
};

//
// Lookup table for increment values based on transfer widths
//
UINT8 mOutStride[] = {
  1, // EfiCpuIoWidthUint8
  2, // EfiCpuIoWidthUint16
  4, // EfiCpuIoWidthUint32
  8, // EfiCpuIoWidthUint64
  1, // EfiCpuIoWidthFifoUint8
  2, // EfiCpuIoWidthFifoUint16
  4, // EfiCpuIoWidthFifoUint32
  8, // EfiCpuIoWidthFifoUint64
  0, // EfiCpuIoWidthFillUint8
  0, // EfiCpuIoWidthFillUint16
  0, // EfiCpuIoWidthFillUint32
  0  // EfiCpuIoWidthFillUint64
};

EFI_STATUS
CpuIoCheckParameter (
  IN BOOLEAN                    MmioOperation,
  IN EFI_CPU_IO_PROTOCOL_WIDTH  Width,
  IN UINT64                     Address,
  IN UINTN                      Count,
  IN VOID                       *Buffer
  )
{
  UINT64  MaxCount;
  UINT64  Limit;

  //
  // Check to see if Buffer is NULL
  //
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check to see if Width is in the valid range
  //
  if ((UINT32)Width >= EfiCpuIoWidthMaximum) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // For FIFO type, the target address won't increase during the access,
  // so treat Count as 1
  //
  if (Width >= EfiCpuIoWidthFifoUint8 && Width <= EfiCpuIoWidthFifoUint64) {
    Count = 1;
  }

  //
  // Check to see if Width is in the valid range for I/O Port operations
  //
  Width = (EFI_CPU_IO_PROTOCOL_WIDTH) (Width & 0x03);
  if (!MmioOperation && (Width == EfiCpuIoWidthUint64)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check to see if Address is aligned
  //
  if ((Address & ((UINT64)mInStride[Width] - 1)) != 0) {
    return EFI_UNSUPPORTED;
  }

  //
  // Check to see if any address associated with this transfer exceeds the maximum
  // allowed address.  The maximum address implied by the parameters passed in is
  // Address + Size * Count.  If the following condition is met, then the transfer
  // is not supported.
  //
  //    Address + Size * Count > (MmioOperation ? MAX_ADDRESS : MAX_IO_PORT_ADDRESS) + 1
  //
  // Since MAX_ADDRESS can be the maximum integer value supported by the CPU and Count
  // can also be the maximum integer value supported by the CPU, this range
  // check must be adjusted to avoid all oveflow conditions.
  //
  // The following form of the range check is equivalent but assumes that
  // MAX_ADDRESS and MAX_IO_PORT_ADDRESS are of the form (2^n - 1).
  //
  Limit = (MmioOperation ? MAX_ADDRESS : MAX_IO_PORT_ADDRESS);
  if (Count == 0) {
    if (Address > Limit) {
      return EFI_UNSUPPORTED;
    }
  } else {
    MaxCount = RShiftU64 (Limit, Width);
    if (MaxCount < (Count - 1)) {
      return EFI_UNSUPPORTED;
    }
    if (Address > LShiftU64 (MaxCount - Count + 1, Width)) {
      return EFI_UNSUPPORTED;
    }
  }

  //
  // Check to see if Buffer is aligned
  // (IA-32 allows UINT64 and INT64 data types to be 32-bit aligned.)
  //
  if (((UINTN)Buffer & ((MIN (sizeof (UINTN), mInStride[Width])  - 1))) != 0) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

UINT64
SecSimLazyContinue (
  IN  UINT64      Steps,
  IN  BOOLEAN     Lazy
  );

EFI_STATUS
EFIAPI
SimicsIoIoRead (
  IN     SIMICS_IO_PPI                          *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH  Width,
  IN     UINT64                                 Address,
  IN     UINTN                                  Count,
  OUT    VOID                                   *Buffer
  )
{
  CHAR8              Cmd[0x50];
  UINTN              CmdLen;
  attr_value_t       ret;
  SIMICS_IO_PRIVATE                             *SimicsIoPrivate;
  EFI_STATUS                 Status;
  UINT8                      InStride;
  UINT8                      OutStride;
  EFI_CPU_IO_PROTOCOL_WIDTH  OperationWidth;
  UINT8                      *Uint8Buffer;

  SecSimLazyContinue(1, FALSE); // update the simics time before access any device

  Status = CpuIoCheckParameter (FALSE, Width, Address, Count, Buffer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SimicsIoPrivate = SIMICS_IO_PRIVATE_FROM_THIS (This);

  //
  // Select loop based on the width of the transfer
  //
  InStride = mInStride[Width];
  OutStride = mOutStride[Width];
  OperationWidth = (EFI_CPU_IO_PROTOCOL_WIDTH) (Width & 0x03);

  //
  // Fifo operations supported for (mInStride[Width] == 0)
  //
  if (InStride == 0) {
    switch (OperationWidth) {
    case EfiCpuIoWidthUint8:
    case EfiCpuIoWidthUint16:
    case EfiCpuIoWidthUint32:
    default:
      //
      // The CpuIoCheckParameter call above will ensure that this
      // path is not taken.
      //
      ASSERT (FALSE);
      break;
    }
  }

  for (Uint8Buffer = Buffer; Count > 0; Address += InStride, Uint8Buffer += OutStride, Count--) {

    ZeroMem(Cmd, sizeof(Cmd));
    CmdLen = sizeof(Cmd);
    CreateSimicsCliCmd(Cmd, &CmdLen, "io_space.read address = 0x%x size = 0x%x", Address, InStride);
    printf("CmdLen=%llu\n", CmdLen);
    printf("Cmd=%s\n", Cmd);
    ret = SIM_run_command(Cmd);
    if (SIM_clear_exception()) {
            printf("Got exception: %s\n", SIM_last_error());
    } else {
            printf("Cmd (%s) return value: ", Cmd);
            print_attribute(ret);
            printf("\n");
    }

    if (OperationWidth == EfiCpuIoWidthUint8) {
      //*Uint8Buffer = IoRead8 ((UINTN)Address);
      *Uint8Buffer = (UINT8) SIM_attr_integer(ret);
    } else if (OperationWidth == EfiCpuIoWidthUint16) {
      //*((UINT16 *)Uint8Buffer) = IoRead16 ((UINTN)Address);
      *((UINT16 *)Uint8Buffer) = (UINT16) SIM_attr_integer(ret);
    } else if (OperationWidth == EfiCpuIoWidthUint32) {
      //*((UINT32 *)Uint8Buffer) = IoRead32 ((UINTN)Address);
      *((UINT32 *)Uint8Buffer) = (UINT32) SIM_attr_integer(ret);
    }

    SIM_attr_free(&ret);
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoIoWrite (
  IN       SIMICS_IO_PPI                           *This,
  IN       EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH   Width,
  IN       UINT64                                  Address,
  IN       UINTN                                   Count,
  IN       VOID                                    *Buffer
  )
{
  CHAR8              Cmd[0x50];
  UINTN              CmdLen;
  attr_value_t       ret;
  SIMICS_IO_PRIVATE          *SimicsIoPrivate;
  EFI_STATUS                 Status;
  UINT8                      InStride;
  UINT8                      OutStride;
  EFI_CPU_IO_PROTOCOL_WIDTH  OperationWidth;
  UINT8                      *Uint8Buffer;

  SecSimLazyContinue(1, FALSE); // update the simics time before access any device

  Status = CpuIoCheckParameter (FALSE, Width, Address, Count, Buffer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SimicsIoPrivate = SIMICS_IO_PRIVATE_FROM_THIS (This);

  //
  // Select loop based on the width of the transfer
  //
  InStride = mInStride[Width];
  OutStride = mOutStride[Width];
  OperationWidth = (EFI_CPU_IO_PROTOCOL_WIDTH) (Width & 0x03);

  //
  // Fifo operations supported for (mInStride[Width] == 0)
  //
  if (InStride == 0) {
    switch (OperationWidth) {
    case EfiCpuIoWidthUint8:
    case EfiCpuIoWidthUint16:
    case EfiCpuIoWidthUint32:
    default:
      //
      // The CpuIoCheckParameter call above will ensure that this
      // path is not taken.
      //
      ASSERT (FALSE);
      break;
    }
  }

  for (Uint8Buffer = (UINT8 *)Buffer; Count > 0; Address += InStride, Uint8Buffer += OutStride, Count--) {
    ZeroMem(Cmd, sizeof(Cmd));
    CmdLen = sizeof(Cmd);

    if (OperationWidth == EfiCpuIoWidthUint8) {
      //IoWrite8 ((UINTN)Address, *Uint8Buffer);
      CreateSimicsCliCmd(Cmd, &CmdLen, "io_space.write address = 0x%x value = 0x%x size = 0x%x", Address, *Uint8Buffer, InStride);
    } else if (OperationWidth == EfiCpuIoWidthUint16) {
      //IoWrite16 ((UINTN)Address, *((UINT16 *)Uint8Buffer));
      CreateSimicsCliCmd(Cmd, &CmdLen, "io_space.write address = 0x%x value = 0x%x size = 0x%x", Address, *((UINT16 *)Uint8Buffer), InStride);
    } else if (OperationWidth == EfiCpuIoWidthUint32) {
      //IoWrite32 ((UINTN)Address, *((UINT32 *)Uint8Buffer));
      CreateSimicsCliCmd(Cmd, &CmdLen, "io_space.write address = 0x%x value = 0x%x size = 0x%x", Address, *((UINT32 *)Uint8Buffer), InStride);
    }

    printf("CmdLen=%llu\n", CmdLen);
    printf("Cmd=%s\n", Cmd);
    ret = SIM_run_command(Cmd);
    if (SIM_clear_exception()) {
            printf("Got exception: %s\n", SIM_last_error());
    } else {
            printf("Cmd (%s) return value: ", Cmd);
            print_attribute(ret);
            SIM_attr_free(&ret);
            printf("\n");
    }
  }

  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
SimicsIoCopyMem (
  IN     SIMICS_IO_PPI                            *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH    Width,
  IN     UINT64                                   DestAddress,
  IN     UINT64                                   SrcAddress,
  IN     UINTN                                    Count
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
SimicsIoMap (
  IN     SIMICS_IO_PPI                              *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION  Operation,
  IN     VOID                                       *HostAddress,
  IN OUT UINTN                                      *NumberOfBytes,
  OUT    EFI_PHYSICAL_ADDRESS                       *DeviceAddress,
  OUT    VOID                                       **Mapping
  )
{
  SIMICS_IO_PRIVATE         *SimicsIoPrivate;
  SimicsIoPrivate = SIMICS_IO_PRIVATE_FROM_THIS (This);

  if (HostAddress == NULL || NumberOfBytes == NULL || DeviceAddress == NULL ||
      Mapping == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Simply convert to the below 4G address
  // Have set Simics Memory Space Offset as the high 32bits value of
  // this process malloc pool address, the Memory Space will help us to do the
  // real mapping from 32bit DMA device address to the 64bit host address
  *DeviceAddress = (UINT64)HostAddress & 0xffffffff;

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoUnmap (
  IN  SIMICS_IO_PPI           *This,
  IN  VOID                    *Mapping
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoAllocateBuffer (
  IN     SIMICS_IO_PPI          *This,
  IN     EFI_ALLOCATE_TYPE      Type,
  IN     EFI_MEMORY_TYPE        MemoryType,
  IN     UINTN                  Pages,
  IN OUT VOID                   **HostAddress,
  IN     UINT64                 Attributes
  )
{
  //EFI_STATUS                Status;
  VOID                      *BufferAddress;
  UINT64                    DmaBarAddress;
  SIMICS_IO_PRIVATE         *SimicsIoPrivate;
  //
  // Validate Attributes
  //
  if ((Attributes & EFI_PCI_ATTRIBUTE_INVALID_FOR_ALLOCATE_BUFFER) != 0) {
    return EFI_UNSUPPORTED;
  }

  //
  // Check for invalid inputs
  //
  if (HostAddress == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // The only valid memory types are EfiBootServicesData and
  // EfiRuntimeServicesData
  //
  if (MemoryType != EfiBootServicesData &&
      MemoryType != EfiRuntimeServicesData) {
    return EFI_INVALID_PARAMETER;
  }

  SimicsIoPrivate = SIMICS_IO_PRIVATE_FROM_THIS (This);

  //
  //  Allocate DMA buffer
  //
  DmaBarAddress = SimicsIoPrivate->DmaBufferOffset;
  //BufferAddress     = VirtualAlloc (DmaBarAddress, (SIZE_T) Pages, MEM_COMMIT, PAGE_READWRITE);
  BufferAddress = malloc(EFI_PAGES_TO_SIZE(Pages));
  if (BufferAddress == NULL) {
    printf ("ERROR : Can not allocate enough space for DMA buffer\n\r");
    return EFI_OUT_OF_RESOURCES;
  }

  if (((UINTN)BufferAddress & 0xffffffff00000000) != DmaBarAddress) {
    printf ("ERROR : Can not allocate DMA buffer inside the 4G bar: 0x%llx\n\r", DmaBarAddress);
    return EFI_OUT_OF_RESOURCES;
  }

  *HostAddress = BufferAddress;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoFreeBuffer (
  IN  SIMICS_IO_PPI          *This,
  IN  UINTN                  Pages,
  IN  VOID                   *HostAddress
  )
{
  free(HostAddress);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoFlush (
  IN SIMICS_IO_PPI  *This
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoGetAttributes (
  IN  SIMICS_IO_PPI          *This,
  OUT UINT64                 *Supports,
  OUT UINT64                 *Attributes
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoSetAttributes (
  IN     SIMICS_IO_PPI            *This,
  IN     UINT64                 Attributes,
  IN OUT UINT64                 *ResourceBase,
  IN OUT UINT64                 *ResourceLength
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SimicsIoConfiguration (
  IN  SIMICS_IO_PPI          *This,
  OUT VOID                   **Resources
  )
{
  return EFI_SUCCESS;
}

VOID
SecSimClearInterrupt (
  VOID
  )
{
  attr_value_t ret = SIM_run_python("cli.conf.sig.object_data.timeout_flag = 0");
  // printf("clear cli.conf.sig.object_data.timeout_flag = 0");
  // print_attribute(ret);
  SIM_attr_free(&ret);
}

extern volatile BOOLEAN        mInterruptEnabled;

BOOLEAN
SecSimCheckInterrupt (
  VOID
  )
{
  int flag = 0;

  //
  // directly return if CPU interrupted has been disabled
  //
  if (!mInterruptEnabled){
    return FALSE;
  }

  attr_value_t ret = SIM_run_python("cli.conf.sig.object_data.timeout_flag");
  //printf("cli.conf.sig.object_data.timeout_flag:");
  //print_attribute(ret);
  flag = (int) SIM_attr_integer(ret);
  SIM_attr_free(&ret);

  if (flag){
    return TRUE;
  }else{
    return FALSE;
  }
}

void
InitSimics(int argc, char *argv[], char *envp[])
{
  UINT64    MemoryMapOffset = 0;

  set_main_thread();

  // set a few parameters for demo purpose
  static init_arg_t init_args[] = {
          {"quiet",    true,  .u.enabled = false},
          {"project",  false, .u.string  = "C:\\Users\\jshi19\\simics-projects\\mysimicsproject"},
          {"gui-mode", false, .u.string  = "no-gui"},
          {"cpu-mode", false, .u.string  = "any"},
          {NULL,       false, .u.string  = NULL}
  };
      
  /* This must come very early, since both text output and memory
     allocation needs it. */
  // https://simics-download.pdx.intel.com/simics-6/docs/html/reference-manual-api/simulator-api-functions.html#SIM_init_environment
  SIM_init_environment(argv,
                       false,    /* don't let Simics handle signals */
                       false);   /* don't allow Simics to dump core */

  /* Initialize the simulator core */
  SIM_init_simulator2(init_args);
  sim_obj = SIM_get_object("sim");
  if (!sim_obj) {
      printf("Couldn't find the \"sim\" object\n");
      SIM_quit(1);
  }

  // attr_value_t ret = SIM_run_command("run-command-file file = \"%simics%/targets/vacuum/vacuum.simics\"");
  // if (SIM_clear_exception()) {
          // printf("Got exception: %s\n", SIM_last_error());
  // } else {
          // printf("Command return value: ");
          // print_attribute(ret);
          // SIM_attr_free(&ret);
          // printf("\n");
  // }

  // mem_obj = SIM_get_object("phys_mem");
  // if (!mem_obj) {
      // printf("Couldn't find the \"phys_mem\" object\n");
      // SIM_quit(1);
  // }

  // ret = SIM_run_command("phys_mem.write 1 100 -l");
  // if (SIM_clear_exception()) {
          // printf("Got exception: %s\n", SIM_last_error());
  // } else {
          // printf("phys_mem.write 1 100 -l return value: ");
          // print_attribute(ret);
          // SIM_attr_free(&ret);
          // printf("\n");
  // }

  // ret = SIM_run_command("phys_mem.read 0 -l");
  // if (SIM_clear_exception()) {
          // printf("Got exception: %s\n", SIM_last_error());
  // } else {
          // printf("phys_mem.read 0 -l return value: ");
          // print_attribute(ret);
          // SIM_attr_free(&ret);
          // printf("\n");
  // }

  // double current_time;
  // current_time = SIM_time(mem_obj);
  // printf("current_time= %f \n", current_time);
  // SIM_run_command("run 1 s");
  // current_time = SIM_time(mem_obj);
  // printf("current_time after run 1 s = %f \n", current_time);
  // SIM_continue(10000000);
  // current_time = SIM_time(mem_obj);
  // printf("current_time after run 10000000 steps = %f \n", current_time);
# if 0
  attr_value_t ret = SIM_run_command("run-python-file filename = \"%simics%/modules/sample-dma-device/test/s-sampledma-go-to-host.py\"");
  if (SIM_clear_exception()) {
          printf("Got exception: %s\n", SIM_last_error());
  } else {
          printf("Command return value: ");
          print_attribute(ret);
          SIM_attr_free(&ret);
          printf("\n");

          dma_obj = SIM_get_object("mydma");
          double current_time;
          current_time = SIM_time(dma_obj);
          printf("current_time= %f \n", current_time);
          SIM_run_command("run 1 s");
          current_time = SIM_time(dma_obj);
          printf("current_time after run 1 s = %f \n", current_time);
          SIM_continue(10000000);
          current_time = SIM_time(dma_obj);
          printf("current_time after run 10000000 steps = %f \n", current_time);

          SIM_run_command("log-level 0");
  }

  MemoryMapOffset = 0;
  ret = SIM_run_command("memory_map->map[0][3]");
  if (SIM_clear_exception()) {
          printf("Got exception: %s\n", SIM_last_error());
  } else {
          printf("memory_map->map[0][3] return value: ");
          print_attribute(ret);
          MemoryMapOffset = SIM_attr_integer(ret);
          SIM_attr_free(&ret);
          printf("\n");
  }

  if(MemoryMapOffset == 0) {
      printf("Error: Memory Map Offset is set to 0");
      return ;
  }
#endif

  ZeroMem (&mSimicsIoPrivate, sizeof (mSimicsIoPrivate));
  SimicsIoPpiPtr = &mSimicsIoPrivate.SimicsIo;
  SimicsIoPpiPtr->Bank.Read        = SimicsIoBankRead;
  SimicsIoPpiPtr->Bank.Write       = SimicsIoBankWrite;
  SimicsIoPpiPtr->Reg.Read         = SimicsIoRegRead;
  SimicsIoPpiPtr->Reg.Write        = SimicsIoRegWrite;
  SimicsIoPpiPtr->PollMem          = SimicsIoPollMem;
  SimicsIoPpiPtr->PollIo           = SimicsIoPollIo;
  SimicsIoPpiPtr->Mem.Read         = SimicsIoMemRead;
  SimicsIoPpiPtr->Mem.Write        = SimicsIoMemWrite;
  SimicsIoPpiPtr->Io.Read          = SimicsIoIoRead;
  SimicsIoPpiPtr->Io.Write         = SimicsIoIoWrite;
  SimicsIoPpiPtr->CopyMem          = SimicsIoCopyMem;
  SimicsIoPpiPtr->Map              = SimicsIoMap;
  SimicsIoPpiPtr->Unmap            = SimicsIoUnmap;
  SimicsIoPpiPtr->AllocateBuffer   = SimicsIoAllocateBuffer;
  SimicsIoPpiPtr->FreeBuffer       = SimicsIoFreeBuffer;
  SimicsIoPpiPtr->Flush            = SimicsIoFlush;
  SimicsIoPpiPtr->GetAttributes    = SimicsIoGetAttributes;
  SimicsIoPpiPtr->SetAttributes    = SimicsIoSetAttributes;
  SimicsIoPpiPtr->Configuration    = SimicsIoConfiguration;
  SimicsIoPpiPtr->CliDevName       = "mydma";
  SimicsIoPpiPtr->CliDevNameLength = AsciiStrSize("mydma");
  //SimicsIoPpiPtr->ClassName        = SIM_object_class(dma_obj)->name;
  //SimicsIoPpiPtr->ClassNameLength  = AsciiStrSize(SimicsIoPpiPtr->ClassName);

  mSimicsIoPrivate.DmaBufferOffset = MemoryMapOffset;

  attr_value_t ret = SIM_run_command("run-python-file filename = \"%simics%/modules/8254/test/timer_tb.py\"");
  if (SIM_clear_exception()) {
          printf("Got exception: %s\n", SIM_last_error());
  } else {
          printf("Command return value: ");
          print_attribute(ret);
          SIM_attr_free(&ret);
          printf("\n");

          // dma_obj = SIM_get_object("mydma");
          // double current_time;
          // current_time = SIM_time(dma_obj);
          // printf("current_time= %f \n", current_time);
          // SIM_run_command("run 1 s");
          // current_time = SIM_time(dma_obj);
          // printf("current_time after run 1 s = %f \n", current_time);
          // SIM_continue(10000000);
          // current_time = SIM_time(dma_obj);
          // printf("current_time after run 10000000 steps = %f \n", current_time);

          SIM_run_command("log-level 1");

          ret = SIM_run_python("cli.conf.sig.object_data.level");
          printf("cli.conf.sig.object_data.level: ");
          print_attribute(ret);
          SIM_attr_free(&ret);
          printf("\n");

          SIM_run_python("cli.conf.sig.object_data.level = 1");
          ret = SIM_run_python("cli.conf.sig.object_data.level");
          printf("cli.conf.sig.object_data.level: ");
          print_attribute(ret);
          SIM_attr_free(&ret);
          printf("\n");
  }


  // attr_value_t ret = SIM_run_command("run-python-file filename = \"%simics%/modules/8254/test/clock.py\"");
  // if (SIM_clear_exception()) {
          // printf("Got exception: %s\n", SIM_last_error());
  // } else {
          // printf("Command return value: ");
          // print_attribute(ret);
          // SIM_attr_free(&ret);
          // printf("\n");

          // SIM_run_command("log-level 0");
  // }

  // SIM_init_command_line();
  // SIM_main_loop();

  // ret = SIM_run_command("run-command-file file = \"%simics%/modules/go-to-host/go-to-host.simics\"");
  // if (SIM_clear_exception()) {
          // printf("Got exception: %s\n", SIM_last_error());
  // } else {
          // printf("Command return value: ");
          // print_attribute(ret);
          // SIM_attr_free(&ret);
          // printf("\n");
  // }

  // go_to_host_dev = SIM_get_object("test.gth");
  // if (!go_to_host_dev) {
      // printf("Couldn't find the \"go-to-host\" object\n");
      // SIM_quit(1);
  // }

  // mem_obj = SIM_get_object("test.memory_map");
  // if (!mem_obj) {
      // printf("Couldn't find the \"test.memory_map\" object\n");
      // SIM_quit(1);
  // }

  // attr_value_t val = SIM_get_attribute(go_to_host_dev, "alloc");
  // VOID *address = (VOID *)SIM_attr_integer(val);

  // printf("target address= 0x%llx\n", address);
  // UINT64 buffer = 0xcafe000100020003;
  // const memory_space_interface_t *mem_space_interface =
          // SIM_c_get_interface(mem_obj, "memory_space");
  // mem_space_interface->access_simple(mem_obj, 0, address, (UINT8 *)&buffer, 8, Sim_RW_Write, Sim_Endian_Target);

  // buffer = 0;
  // mem_space_interface->access_simple(mem_obj, 0, address, (UINT8 *)&buffer, 8, Sim_RW_Read, Sim_Endian_Target);
  // printf("buffer= 0x%llx\n", buffer);
  // mem_space_interface->access_simple(mem_obj, 0, address, (UINT8 *)&buffer, 8, Sim_RW_Read, Sim_Endian_Host_From_BE);
  // printf("buffer= 0x%llx\n", buffer);


  // SIM_init_command_line();
  // SIM_main_loop();

  return;
}

