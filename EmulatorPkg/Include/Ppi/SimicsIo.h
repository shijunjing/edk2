/** @file
  Interface to access Simics Device

  Copyright (c) 2022, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SIMICS_IO_PPI_H__
#define __SIMICS_IO_PPI_H__

#include <Uefi.h>
#include <Library/BaseLib.h>

typedef struct _SIMICS_IO_PPI  SIMICS_IO_PPI;

///
/// *******************************************************
/// EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH
/// *******************************************************
///
typedef enum {
  EfiPciWidthUint8,
  EfiPciWidthUint16,
  EfiPciWidthUint32,
  EfiPciWidthUint64,
  EfiPciWidthFifoUint8,
  EfiPciWidthFifoUint16,
  EfiPciWidthFifoUint32,
  EfiPciWidthFifoUint64,
  EfiPciWidthFillUint8,
  EfiPciWidthFillUint16,
  EfiPciWidthFillUint32,
  EfiPciWidthFillUint64,
  EfiPciWidthMaximum
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH;

///
/// *******************************************************
/// EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION
/// *******************************************************
///
typedef enum {
  ///
  /// A read operation from system memory by a bus master that is not capable of producing
  /// PCI dual address cycles.
  ///
  EfiPciOperationBusMasterRead,
  ///
  /// A write operation from system memory by a bus master that is not capable of producing
  /// PCI dual address cycles.
  ///
  EfiPciOperationBusMasterWrite,
  ///
  /// Provides both read and write access to system memory by both the processor and a bus
  /// master that is not capable of producing PCI dual address cycles.
  ///
  EfiPciOperationBusMasterCommonBuffer,
  ///
  /// A read operation from system memory by a bus master that is capable of producing PCI
  /// dual address cycles.
  ///
  EfiPciOperationBusMasterRead64,
  ///
  /// A write operation to system memory by a bus master that is capable of producing PCI
  /// dual address cycles.
  ///
  EfiPciOperationBusMasterWrite64,
  ///
  /// Provides both read and write access to system memory by both the processor and a bus
  /// master that is capable of producing PCI dual address cycles.
  ///
  EfiPciOperationBusMasterCommonBuffer64,
  EfiPciOperationMaximum
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION;

#define EFI_PCI_ATTRIBUTE_ISA_MOTHERBOARD_IO          0x0001
#define EFI_PCI_ATTRIBUTE_ISA_IO                      0x0002
#define EFI_PCI_ATTRIBUTE_VGA_PALETTE_IO              0x0004
#define EFI_PCI_ATTRIBUTE_VGA_MEMORY                  0x0008
#define EFI_PCI_ATTRIBUTE_VGA_IO                      0x0010
#define EFI_PCI_ATTRIBUTE_IDE_PRIMARY_IO              0x0020
#define EFI_PCI_ATTRIBUTE_IDE_SECONDARY_IO            0x0040
#define EFI_PCI_ATTRIBUTE_MEMORY_WRITE_COMBINE        0x0080
#define EFI_PCI_ATTRIBUTE_MEMORY_CACHED               0x0800
#define EFI_PCI_ATTRIBUTE_MEMORY_DISABLE              0x1000
#define EFI_PCI_ATTRIBUTE_DUAL_ADDRESS_CYCLE          0x8000
#define EFI_PCI_ATTRIBUTE_ISA_IO_16                   0x10000
#define EFI_PCI_ATTRIBUTE_VGA_PALETTE_IO_16           0x20000
#define EFI_PCI_ATTRIBUTE_VGA_IO_16                   0x40000

#define EFI_PCI_ATTRIBUTE_VALID_FOR_ALLOCATE_BUFFER   (EFI_PCI_ATTRIBUTE_MEMORY_WRITE_COMBINE | EFI_PCI_ATTRIBUTE_MEMORY_CACHED | EFI_PCI_ATTRIBUTE_DUAL_ADDRESS_CYCLE)

#define EFI_PCI_ATTRIBUTE_INVALID_FOR_ALLOCATE_BUFFER (~EFI_PCI_ATTRIBUTE_VALID_FOR_ALLOCATE_BUFFER)

#define EFI_PCI_ADDRESS(bus, dev, func, reg) \
  (UINT64) ( \
  (((UINTN) bus) << 24) | \
  (((UINTN) dev) << 16) | \
  (((UINTN) func) << 8) | \
  (((UINTN) (reg)) < 256 ? ((UINTN) (reg)) : (UINT64) (LShiftU64 ((UINT64) (reg), 32))))

typedef struct {
  UINT8   Register;
  UINT8   Function;
  UINT8   Device;
  UINT8   Bus;
  UINT32  ExtendedRegister;
} EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS;


/**
  Access Simics device register through its bank name and offset
  https://simics-download.pdx.intel.com/simics-6/docs/html/model-builder-user-guide/programming-with-dml.html#spc-dml-banks-and-registers

  @param  BankName              The bank name string.
  @param  Offset                The register offset in the bank.
  @param  Size                  The register size, optional.
  @param  Count                 The number of memory operations to perform.
  @param  Buffer                For read operations, the destination buffer to store the results. For write
                                operations, the source buffer to write data from.

  @retval EFI_SUCCESS           The data was read from or written to the Simics device.
  @retval EFI_OUT_OF_RESOURCES  The request could not be completed due to a lack of resources.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_ACCESS_REG_FROM_BANK)(
  IN     SIMICS_IO_PPI    *This,
  IN     CHAR8            *BankName,
  IN     UINTN            Offset,
  IN     UINTN            Size,
  IN     UINTN            Count,
  IN OUT VOID             *Buffer
  );

/**
  Access Simics device register through its register name
  https://simics-download.pdx.intel.com/simics-6/docs/html/model-builder-user-guide/programming-with-dml.html#spc-dml-banks-and-registers

  @param  RegName               The register name string.
  @param  Count                 The number of memory operations to perform.
  @param  Buffer                For read operations, the destination buffer to store the results. For write
                                operations, the source buffer to write data from.

  @retval EFI_SUCCESS           The data was read from or written to the Simics device.
  @retval EFI_OUT_OF_RESOURCES  The request could not be completed due to a lack of resources.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_ACCESS_REG_NAME)(
  IN     SIMICS_IO_PPI    *This,
  IN     CHAR8            *RegName,
  IN     UINTN            Count,
  IN OUT VOID             *Buffer
  );


typedef struct {
  ///
  /// Read a register in the register banks.
  ///
  SIMICS_ACCESS_REG_FROM_BANK  Read;
  ///
  /// Write a register in the register banks.
  ///
  SIMICS_ACCESS_REG_FROM_BANK  Write;
} SIMICS_IO_ACCESS_REG_VIA_BANK;

typedef struct {
  ///
  /// Read a register in the register banks.
  ///
  SIMICS_ACCESS_REG_NAME       Read;
  ///
  /// Write a register in the register banks.
  ///
  SIMICS_ACCESS_REG_NAME       Write;
} SIMICS_IO_ACCESS_REG_VIA_NAME;


/**
  Enables a PCI driver to copy one region of PCI root bridge memory space to another region of PCI
  root bridge memory space.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL instance.
  @param  Width                 Signifies the width of the memory operations.
  @param  DestAddress           The destination address of the memory operation.
  @param  SrcAddress            The source address of the memory operation.
  @param  Count                 The number of memory operations to perform.

  @retval EFI_SUCCESS           The data was copied from one memory region to another memory region.
  @retval EFI_INVALID_PARAMETER Width is invalid for this PCI root bridge.
  @retval EFI_OUT_OF_RESOURCES  The request could not be completed due to a lack of resources.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_COPY_MEM)(
  IN     SIMICS_IO_PPI                            *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH    Width,
  IN     UINT64                                   DestAddress,
  IN     UINT64                                   SrcAddress,
  IN     UINTN                                    Count
  );

/**
  Provides the PCI controller-specific addresses required to access system memory from a
  DMA bus master.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Operation             Indicates if the bus master is going to read or write to system memory.
  @param  HostAddress           The system memory address to map to the PCI controller.
  @param  NumberOfBytes         On input the number of bytes to map. On output the number of bytes
                                that were mapped.
  @param  DeviceAddress         The resulting map address for the bus master PCI controller to use to
                                access the hosts HostAddress.
  @param  Mapping               A resulting value to pass to Unmap().

  @retval EFI_SUCCESS           The range was mapped for the returned NumberOfBytes.
  @retval EFI_UNSUPPORTED       The HostAddress cannot be mapped as a common buffer.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES  The request could not be completed due to a lack of resources.
  @retval EFI_DEVICE_ERROR      The system hardware could not map the requested address.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_MAP)(
  IN     SIMICS_IO_PPI                              *This,
  IN     EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION  Operation,
  IN     VOID                                       *HostAddress,
  IN OUT UINTN                                      *NumberOfBytes,
  OUT    EFI_PHYSICAL_ADDRESS                       *DeviceAddress,
  OUT    VOID                                       **Mapping
  );


/**
  Completes the Map() operation and releases any corresponding resources.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Mapping               The mapping value returned from Map().

  @retval EFI_SUCCESS           The range was unmapped.
  @retval EFI_INVALID_PARAMETER Mapping is not a value that was returned by Map().
  @retval EFI_DEVICE_ERROR      The data was not committed to the target system memory.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_UNMAP)(
  IN  SIMICS_IO_PPI           *This,
  IN  VOID                    *Mapping
  );

/**
  Allocates pages that are suitable for an EfiPciOperationBusMasterCommonBuffer or
  EfiPciOperationBusMasterCommonBuffer64 mapping.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Type                  This parameter is not used and must be ignored.
  @param  MemoryType            The type of memory to allocate, EfiBootServicesData or
                                EfiRuntimeServicesData.
  @param  Pages                 The number of pages to allocate.
  @param  HostAddress           A pointer to store the base system memory address of the
                                allocated range.
  @param  Attributes            The requested bit mask of attributes for the allocated range.

  @retval EFI_SUCCESS           The requested memory pages were allocated.
  @retval EFI_UNSUPPORTED       Attributes is unsupported. The only legal attribute bits are
                                MEMORY_WRITE_COMBINE and MEMORY_CACHED.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES  The memory pages could not be allocated.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_ALLOCATE_BUFFER)(
  IN     SIMICS_IO_PPI          *This,
  IN     EFI_ALLOCATE_TYPE      Type,
  IN     EFI_MEMORY_TYPE        MemoryType,
  IN     UINTN                  Pages,
  IN OUT VOID                   **HostAddress,
  IN     UINT64                 Attributes
  );

/**
  Frees memory that was allocated with AllocateBuffer().

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Pages                 The number of pages to free.
  @param  HostAddress           The base system memory address of the allocated range.

  @retval EFI_SUCCESS           The requested memory pages were freed.
  @retval EFI_INVALID_PARAMETER The memory range specified by HostAddress and Pages
                                was not allocated with AllocateBuffer().

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_FREE_BUFFER)(
  IN  SIMICS_IO_PPI          *This,
  IN  UINTN                  Pages,
  IN  VOID                   *HostAddress
  );

/**
  Flushes all PCI posted write transactions from a PCI host bridge to system memory.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.

  @retval EFI_SUCCESS           The PCI posted write transactions were flushed from the PCI host
                                bridge to system memory.
  @retval EFI_DEVICE_ERROR      The PCI posted write transactions were not flushed from the PCI
                                host bridge due to a hardware error.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_FLUSH)(
  IN SIMICS_IO_PPI  *This
  );

/**
  Gets the attributes that a PCI root bridge supports setting with SetAttributes(), and the
  attributes that a PCI root bridge is currently using.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Supports              A pointer to the mask of attributes that this PCI root bridge supports
                                setting with SetAttributes().
  @param  Attributes            A pointer to the mask of attributes that this PCI root bridge is currently
                                using.

  @retval EFI_SUCCESS           If Supports is not NULL, then the attributes that the PCI root
                                bridge supports is returned in Supports. If Attributes is
                                not NULL, then the attributes that the PCI root bridge is currently
                                using is returned in Attributes.
  @retval EFI_INVALID_PARAMETER Both Supports and Attributes are NULL.


**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_GET_ATTRIBUTES)(
  IN  SIMICS_IO_PPI          *This,
  OUT UINT64                 *Supports,
  OUT UINT64                 *Attributes
  );

/**
  Sets attributes for a resource range on a PCI root bridge.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Attributes            The mask of attributes to set.
  @param  ResourceBase          A pointer to the base address of the resource range to be modified by the
                                attributes specified by Attributes.
  @param  ResourceLength        A pointer to the length of the resource range to be modified by the
                                attributes specified by Attributes.

  @retval EFI_SUCCESS           The set of attributes specified by Attributes for the resource
                                range specified by ResourceBase and ResourceLength
                                were set on the PCI root bridge, and the actual resource range is
                                returned in ResuourceBase and ResourceLength.
  @retval EFI_UNSUPPORTED       A bit is set in Attributes that is not supported by the PCI Root
                                Bridge.
  @retval EFI_OUT_OF_RESOURCES  There are not enough resources to set the attributes on the
                                resource range specified by BaseAddress and Length.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_SET_ATTRIBUTES)(
  IN     SIMICS_IO_PPI            *This,
  IN     UINT64                 Attributes,
  IN OUT UINT64                 *ResourceBase,
  IN OUT UINT64                 *ResourceLength
  );

/**
  Retrieves the current resource settings of this PCI root bridge in the form of a set of ACPI
  resource descriptors.

  @param  This                  A pointer to the EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL.
  @param  Resources             A pointer to the resource descriptors that describe the current
                                configuration of this PCI root bridge.

  @retval EFI_SUCCESS           The current configuration of this PCI root bridge was returned in
                                Resources.
  @retval EFI_UNSUPPORTED       The current configuration of this PCI root bridge could not be
                                retrieved.

**/
typedef
EFI_STATUS
(EFIAPI *SIMICS_IO_CONFIGURATION)(
  IN  SIMICS_IO_PPI          *This,
  OUT VOID                   **Resources
  );


//Borrow EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL to define Simics device IO interface
struct _SIMICS_IO_PPI{
  SIMICS_IO_ACCESS_REG_VIA_BANK   Bank;
  SIMICS_IO_ACCESS_REG_VIA_NAME   Reg;
  SIMICS_IO_COPY_MEM              CopyMem;
  SIMICS_IO_MAP                   Map;
  SIMICS_IO_UNMAP                 Unmap;
  SIMICS_IO_ALLOCATE_BUFFER       AllocateBuffer;
  SIMICS_IO_FREE_BUFFER           FreeBuffer;
  SIMICS_IO_FLUSH                 Flush;
  SIMICS_IO_GET_ATTRIBUTES        GetAttributes;
  SIMICS_IO_SET_ATTRIBUTES        SetAttributes;
  SIMICS_IO_CONFIGURATION         Configuration;
  UINT16                          CliDevNameLength;  // CLI device object name string length
  CONST CHAR8                     *CliDevName;       // CLI device object name string, like Uefi device path
  UINT16                          ClassNameLength;
  CONST CHAR8                     *ClassName;
} ;

extern EFI_GUID gSimicsIoPpiGuid;

#endif
