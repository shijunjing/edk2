#include <simics/module-host-config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

//#include <unistd.h>

#include <simics/simulator-api.h>


#ifdef _WIN32
typedef jmp_buf sigjmp_buf;
#define sigsetjmp(env, _n) setjmp(env)
#endif /* _WIN32 */