/** @file
 UEFI PEIM demo to bypass instruction set simulator and
 directly access Simics device models

Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/



//
// The package level header files this module uses
//
#include <PiPei.h>

#include <Library/PcdLib.h>
#include <Library/PeiServicesLib.h>


//
// The protocols, PPI and GUID defintions for this module
//
#include <Uefi/UefiSpec.h>
#include <Ppi/SimicsIo.h>
//
// The Library classes this module consumes
//
#include <Library/DebugLib.h>
#include <Library/PeimEntryPoint.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
//
// Module globals
//
EFI_PEI_PPI_DESCRIPTOR  mPpiListBootMode = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiMasterBootModePpiGuid,
  NULL
};

EFI_PEI_PPI_DESCRIPTOR  mPpiListRecoveryBootMode = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiBootInRecoveryModePpiGuid,
  NULL
};

EFI_STATUS
EFIAPI
InitSampleDmaDevice (
  IN       EFI_PEI_FILE_HANDLE       FileHandle,
  IN CONST EFI_PEI_SERVICES          **PeiServices
  )
/*++

Routine Description:

  Perform DMA transfers in OS host memory through Simics DMA device

Arguments:

  PeiServices - General purpose services available to every PEIM.

Returns:

  Status -  EFI_SUCCESS if the boot mode could be set

**/
{
  EFI_STATUS                  Status;
  EFI_PEI_PPI_DESCRIPTOR      *PpiDescriptor;
  SIMICS_IO_PPI               *SimicsIo;
  VOID                        *SrcBuffer;
  VOID                        *DestBuffer;
  UINTN                       Pages;
  UINTN                       Bytes;
  VOID                        *SrcMapping;
  EFI_PHYSICAL_ADDRESS        SrcDeviceAddr;
  VOID                        *DestMapping;
  EFI_PHYSICAL_ADDRESS        DestDeviceAddr;
  UINT32                      RegValue32;
  UINT32                      TestBuffer1, TestBuffer2;
  UINTN                       AddrBuffer;
  // CHAR8                       *NameStr;

  DEBUG ((EFI_D_ERROR, "PEI driver of Simics sample dma device is loaded\n"));

  //
  // Get the Simics Device Reg PPI
  //
  Status = PeiServicesLocatePpi (
              &gSimicsIoPpiGuid,          // GUID
              0,                          // INSTANCE
              &PpiDescriptor,             // EFI_PEI_PPI_DESCRIPTOR
              (VOID **)&SimicsIo          // PPI
              );
  ASSERT_EFI_ERROR (Status);

  // DEBUG ((EFI_D_ERROR, "the simics device name length= %d\n", SimicsIo->CliDevNameLength));
  // NameStr = AllocateCopyPool(SimicsIo->CliDevNameLength, SimicsIo->CliDevName);
  DEBUG ((EFI_D_ERROR, "the device obj name: %a\n", SimicsIo->CliDevName));
  DEBUG ((EFI_D_ERROR, "the device class name: %a\n", SimicsIo->ClassName));

  if (AsciiStrCmp(SimicsIo->ClassName, "sample_dma_device") != 0){
    return EFI_UNSUPPORTED;
  }

  DEBUG ((EFI_D_ERROR, "TestBuffer1 address= 0x%lx\n", &TestBuffer1));
  DEBUG ((EFI_D_ERROR, "TestBuffer2 address= 0x%lx\n", &TestBuffer2));

  TestBuffer1 = 0x12345678;
  TestBuffer2 = 0x0;
  DEBUG ((EFI_D_ERROR, "Before DMA, TestBuffer1= 0x%x\n", TestBuffer1));
  DEBUG ((EFI_D_ERROR, "Before DMA, TestBuffer2= 0x%x\n", TestBuffer2));
  AddrBuffer = (UINTN) &TestBuffer1;
  SimicsIo->Bank.Write(SimicsIo, "regs", 4, 4, 4, &AddrBuffer); //DMA_source
  AddrBuffer = (UINTN) &TestBuffer2;
  SimicsIo->Bank.Write(SimicsIo, "regs", 8, 4, 4, &AddrBuffer); //DMA_dest
  RegValue32 = 0x1 << 31 | 0x1 << 30 | 0x1; // set EN | SWT | TS
  SimicsIo->Bank.Write(SimicsIo, "regs", 0, 4, 4, &RegValue32);
  DEBUG ((EFI_D_ERROR, "After DMA, TestBuffer1= 0x%x\n", TestBuffer1));
  DEBUG ((EFI_D_ERROR, "After DMA, TestBuffer2= 0x%x\n", TestBuffer2));
  //return EFI_SUCCESS;

  //
  //Allocate source device DMA buffer
  //
  Pages = 1;
  Status = SimicsIo->AllocateBuffer (
                      SimicsIo,
                      AllocateAnyPages,
                      EfiBootServicesData,
                      Pages,
                      &SrcBuffer,
                      0
                      );
  ASSERT_EFI_ERROR (Status);
  *(UINT64 *)SrcBuffer = 0xcafe000100020003;

  Bytes  = EFI_PAGES_TO_SIZE (Pages);
  //
  //Convert host address to device address
  //
  Status = SimicsIo->Map (
                    SimicsIo,
                    EfiPciOperationBusMasterCommonBuffer,
                    SrcBuffer,
                    &Bytes,
                    &SrcDeviceAddr,
                    &SrcMapping
                    );
  ASSERT_EFI_ERROR (Status);
  //
  //Allocate destination device DMA buffer
  //
  Status = SimicsIo->AllocateBuffer (
                      SimicsIo,
                      AllocateAnyPages,
                      EfiBootServicesData,
                      Pages,
                      &DestBuffer,
                      0
                      );
  ASSERT_EFI_ERROR (Status);
  *(UINT64 *)DestBuffer = 0;
  //
  //Convert host address to device address
  //
  Bytes  = EFI_PAGES_TO_SIZE (Pages);
  Status = SimicsIo->Map (
                    SimicsIo,
                    EfiPciOperationBusMasterCommonBuffer,
                    DestBuffer,
                    &Bytes,
                    &DestDeviceAddr,
                    &DestMapping
                    );
  ASSERT_EFI_ERROR (Status);

  //Program the DMA device registers
  // param register_size = 4;
  // register DMA_control @ 0x00 "Control register";
  // register DMA_source  @ 0x04 "Source address";
  // register DMA_dest    @ 0x08 "Destination address";
  SimicsIo->Bank.Write(SimicsIo, "regs", 4, 4, 4, &SrcDeviceAddr);
  SimicsIo->Bank.Write(SimicsIo, "regs", 8, 4, 4, &DestDeviceAddr);
  RegValue32 = 0x1 << 31 | 0x1 << 30 | 0x2; // set EN | SWT | TS
  SimicsIo->Bank.Write(SimicsIo, "regs", 0, 4, 4, &RegValue32);

  //Check DMA transfer result
  ASSERT(*(UINT64 *)DestBuffer == 0xcafe000100020003);

  //Free all DMA buffers
  SimicsIo->Unmap (SimicsIo, SrcMapping);
  SimicsIo->Unmap (SimicsIo, DestMapping);
  SimicsIo->FreeBuffer (SimicsIo, Pages, SrcBuffer);
  SimicsIo->FreeBuffer (SimicsIo, Pages, DestBuffer);

  return EFI_SUCCESS;
}
