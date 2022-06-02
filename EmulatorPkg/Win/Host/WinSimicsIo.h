#ifndef _WIN_SIMICS_IO_H_
#define _WIN_SIMICS_IO_H_

/*
  code copied from simics-base\core\src\misc\simple-simics\simple-simics.c
*/
#include <simics/module-host-config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <time.h>
#include <ctype.h>



#include <simics/simulator-api.h>
#include <simics/devs/memory-space.h>

//#include <simics/simulator/internal.h>
EXPORTED void VT_logit(const char *NOTNULL str);

//#include <simics/util/os.h>
#define strdup _strdup
void os_path_join(strbuf_t *path, const char *name);
bool os_file_exists(const char *filename);
FILE *os_fopen(const char *path, const char *mode);

#include <simics/internal/control.h>
#include <simics/internal/front.h>

//#include <simics/internal/license.h>
EXPORTED bool VT_dont_use_license_feature(const char *NOTNULL feature_name);

#include <simics/internal/deprecation.h>
#include <simics/simulator/control.h>
#include <simics/util/vect.h>

#include "../core/common/configuration.h"

#ifdef _WIN32
typedef jmp_buf sigjmp_buf;
#define sigsetjmp(env, _n) setjmp(env)
#endif /* _WIN32 */

#include "WinHost.h"
#include <Protocol/CpuIo2.h>


#define SIMICS_IO_SIGNATURE SIGNATURE_32 ('s', 'c', 'i', 'o')

typedef struct {
  UINT32                            Signature;
  LIST_ENTRY                        Link;
  EFI_HANDLE                        Handle;
  UINT64                            AllocationAttributes;
  UINT64                            Attributes;
  UINT64                            Supports;
//   PCI_RES_NODE                      ResAllocNode[TypeMax];
//   PCI_ROOT_BRIDGE_APERTURE          Bus;
//   PCI_ROOT_BRIDGE_APERTURE          Io;
//   PCI_ROOT_BRIDGE_APERTURE          Mem;
//   PCI_ROOT_BRIDGE_APERTURE          PMem;
//   PCI_ROOT_BRIDGE_APERTURE          MemAbove4G;
//   PCI_ROOT_BRIDGE_APERTURE          PMemAbove4G;
  BOOLEAN                           DmaAbove4G;
  BOOLEAN                           NoExtendedConfigSpace;
  VOID                              *ConfigBuffer;
  EFI_DEVICE_PATH_PROTOCOL          *DevicePath;
  CHAR16                            *DevicePathStr;
  SIMICS_IO_PPI                     SimicsIo;
  UINT64                            DmaBufferOffset;

  BOOLEAN                           ResourceSubmitted;
  LIST_ENTRY                        Maps;
} SIMICS_IO_PRIVATE;

#define SIMICS_IO_PRIVATE_FROM_THIS(a) CR (a, SIMICS_IO_PRIVATE, SimicsIo, SIMICS_IO_SIGNATURE)

#define SIMICS_IO_PRIVATE_FROM_LINK(a) CR (a, SIMICS_IO_PRIVATE, Link, SIMICS_IO_SIGNATURE)


#endif