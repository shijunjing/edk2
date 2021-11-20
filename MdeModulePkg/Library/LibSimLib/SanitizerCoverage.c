/** @file
  The compiler instrumentation routines for AddressSanitizer(ASan).

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include <Uefi.h>
#include <PiPei.h>
//#include <Library/SanitizerCoverage.h>
#include <Library/DebugLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PrintLib.h>
#include <Library/EmuMagicPageLib.h>
#include <Library/BaseMemoryLib.h>
#include <Ppi/EmuThunk.h>

VOID
SerialOutput(
  IN  CONST CHAR8      *String
  );

EMU_THUNK_PROTOCOL     *Emu_Thunk = NULL;
UINT64                 *Guard_Executed = NULL;
/**
  This service enables PEIMs to discover a given instance of an interface.

  So this is, well a hack, so we can reuse the same libraries as the PEI Core
  for XIP modules....

  @param  Guid                  A pointer to the GUID whose corresponding interface needs to be
                                found.
  @param  Instance              The N-th instance of the interface that is required.
  @param  PpiDescriptor         A pointer to instance of the EFI_PEI_PPI_DESCRIPTOR.
  @param  Ppi                   A pointer to the instance of the interface.

  @retval EFI_SUCCESS           The interface was successfully returned.
  @retval EFI_NOT_FOUND         The PPI descriptor is not found in the database.

**/
EFI_STATUS
EFIAPI
LocateEmuThunkPpi (
  IN CONST EFI_GUID             *Guid,
  IN UINTN                      Instance,
  IN OUT EFI_PEI_PPI_DESCRIPTOR **PpiDescriptor,
  IN OUT VOID                   **Ppi
  )
{
  EFI_PEI_PPI_DESCRIPTOR *PpiList;

  if (Instance != 0) {
    return EFI_NOT_FOUND;
  }

  for (PpiList = EMU_MAGIC_PAGE()->PpiList; ; PpiList++) {
    if (CompareGuid (PpiList->Guid, Guid)) {
      if (PpiDescriptor != NULL) {
        *PpiDescriptor = PpiList;
      }
      if (Ppi != NULL) {
        *Ppi = PpiList->Ppi;
      }
      return EFI_SUCCESS;
    }

    if ((PpiList->Flags & EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST) == EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST) {
      break;
    }
  }


  return EFI_NOT_FOUND;
}

VOID
ThunkPrint (
  CHAR8  *Format,
  ...
  )
{
  VA_LIST                   Marker;
  UINTN                     CharCount;
  CHAR8                     Buffer[0x1000];
  EFI_STATUS                Status;
  EMU_THUNK_PPI             *ThunkPpi;

  if (Emu_Thunk == NULL){
      //
      // Locate EmuThunkPpi for retrieving standard output handle
      //
      Status = LocateEmuThunkPpi (
                  &gEmuThunkPpiGuid,
                  0,
                  NULL,
                  (VOID **) &ThunkPpi
                 );
      if (!EFI_ERROR (Status)) {
        Emu_Thunk  = (EMU_THUNK_PROTOCOL *)ThunkPpi->Thunk ();
      }
  }

  if (Emu_Thunk){
      //
      // Convert message to ASCII String and print out
      //
      VA_START (Marker, Format);
      AsciiVSPrint (Buffer, sizeof(Buffer), Format, Marker);
      VA_END (Marker);
      CharCount = AsciiStrLen(Buffer);
      Emu_Thunk->WriteStdErr ((UINT8 *)Buffer, CharCount);
  }
}


extern UINT64 __start___sancov_cntrs;
extern UINT8 __stop___sancov_cntrs;
extern UINT64 __start___sancov_guards;
extern UINT8 __stop___sancov_guards;
extern UINT64 __start___sancov_pcs;
extern UINT8 __stop___sancov_pcs;


// Symbolizes the supplied 'pc' using the format string 'fmt'.
// Outputs at most 'out_buf_size' bytes into 'out_buf'.
// If 'out_buf' is not empty then output is zero or more non empty C strings
// followed by single empty C string. Multiple strings can be returned if PC
// corresponds to inlined function. Inlined frames are printed in the order
// from "most-inlined" to the "least-inlined", so the last frame should be the
// not inlined function.
// Inlined frames can be removed with 'symbolize_inline_frames=0'.
// The format syntax is described in
// lib/sanitizer_common/sanitizer_stacktrace_printer.h.
void __sanitizer_symbolize_pc(void *pc, const char *fmt, char *out_buf,
                              size_t out_buf_size);
// Same as __sanitizer_symbolize_pc, but for data section (i.e. globals).
void __sanitizer_symbolize_global(void *data_ptr, const char *fmt,
                                  char *out_buf, size_t out_buf_size);

// clang only support no_sanitize("coverage") attribute if
// compiler-rt project is enabled when build LLVM/Clang compiler
// __attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc_guard_init(UINT32* start, UINT32* stop) {
  //if (start == end || *start) return;
  //SerialOutput (__FILE__);

  static UINT64 N;  // Counter for the guards.
  if (start == stop || *start) return;  // Initialize only once.
  //DEBUG ((EFI_D_ERROR, "__sanitizer_cov_trace_pc_guard_init, start=0x%x, stop=0x%x\n",start, stop));

  for (UINT32 *x = start; x < stop; x++)
    *x = ++N;  // Guards should start from 1.

  ThunkPrint ("Total BB Count= 0x%x\n", N);
}

// clang only support no_sanitize("coverage") attribute if
// compiler-rt project is enabled when build LLVM/Clang compiler
// __attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc_guard(UINT32* guard) {
  EFI_STATUS                Status;
  EMU_THUNK_PPI             *ThunkPpi;

  if (!*guard) return;

  //void *PC = __builtin_return_address(0);
  //char PcDescr[1024];
  // This function is a part of the sanitizer run-time.
  // To use it, link with AddressSanitizer or other sanitizer.
  //__sanitizer_symbolize_pc(PC, "%p %F %L", PcDescr, sizeof(PcDescr));
  //printf("guard: %p %x PC %s\n", guard, *guard, PcDescr);
  //DEBUG ((EFI_D_ERROR, "guard=0x%x, *guard=0x%x, PC=0x%x\n",guard, *guard, PC));
  //ThunkPrint ("guard:0x%x *guard:0x%x PC:0x%x\n", guard, *guard, PC);
  ThunkPrint ("BB:0x%x\n", *guard);

  if (!Guard_Executed){
      //
      // Locate EmuThunkPpi for retrieving standard output handle
      //
      Status = LocateEmuThunkPpi (
                  &gEmuThunkPpiGuid,
                  0,
                  NULL,
                  (VOID **) &ThunkPpi
                 );
      if (!EFI_ERROR (Status)) {
        Emu_Thunk  = (EMU_THUNK_PROTOCOL *)ThunkPpi->Thunk ();
        Guard_Executed = &Emu_Thunk->GuardCountExecuted;
        (*Guard_Executed)++;
      }
  } else{
      (*Guard_Executed)++;
  }
}

// clang only support no_sanitize("coverage") attribute if
// compiler-rt project is enabled when build LLVM/Clang compiler
// __attribute__((no_sanitize("coverage")))
RETURN_STATUS
EFIAPI
LibSimConstructor (
  VOID
  )
{

  __sanitizer_cov_trace_pc_guard_init(&__start___sancov_guards, &__stop___sancov_guards);
  //SerialOutput ("LibSimConstructor done\n");
  return RETURN_SUCCESS;
}