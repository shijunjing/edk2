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
//#include <Library/SanitizerCoverage.h>
#include <Library/DebugLib.h>

VOID
SerialOutput(
  IN  CONST CHAR8      *String
  );

VOID
SecPrint (
  CHAR8  *Format,
  ...
  );

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
  DEBUG ((EFI_D_ERROR, "__sanitizer_cov_trace_pc_guard_init, start=0x%x, stop=0x%x\n",start, stop));

  for (UINT32 *x = start; x < stop; x++)
    *x = ++N;  // Guards should start from 1.

  DEBUG ((EFI_D_ERROR, "Total BB Count= 0x%x\n", N));
}

// clang only support no_sanitize("coverage") attribute if
// compiler-rt project is enabled when build LLVM/Clang compiler
// __attribute__((no_sanitize("coverage")))
void __sanitizer_cov_trace_pc_guard(UINT32* guard) {
  if (!*guard) return;

  //void *PC = __builtin_return_address(0);
  //char PcDescr[1024];
  // This function is a part of the sanitizer run-time.
  // To use it, link with AddressSanitizer or other sanitizer.
  //__sanitizer_symbolize_pc(PC, "%p %F %L", PcDescr, sizeof(PcDescr));
  //printf("guard: %p %x PC %s\n", guard, *guard, PcDescr);
  //DEBUG ((EFI_D_ERROR, "guard=0x%x, *guard=0x%x, PC=0x%x\n",guard, *guard, PC));
  DEBUG ((EFI_D_ERROR, "BB:0x%x\n", *guard));
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