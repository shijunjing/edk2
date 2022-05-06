/* This Software is part of Simics. The rights to copy, distribute,
   modify, or otherwise make use of this Software may be licensed only
   pursuant to the terms of an applicable license agreement.

   Copyright 2017-2021 Intel Corporation */

#ifndef SIMICS_INIT_ARG_H
#define SIMICS_INIT_ARG_H

/* Internal helper functions for init arguments */

static init_arg_t *
find_init_arg(const char *name)
{
        for (int i = 0; INIT_ARGS_NAME[i].name; i++) {
                if (strcmp(name, INIT_ARGS_NAME[i].name) == 0)
                        return &INIT_ARGS_NAME[i];
        }
        return NULL;
}

static void
set_init_arg_string(const char *name, const char *value)
{ 
        init_arg_t *arg = find_init_arg(name);
        ASSERT(arg);
        ASSERT(arg->boolean == false);
        arg->u.string = value;
}

static void
set_init_arg_boolean(const char *name, bool value)
{
        init_arg_t *arg = find_init_arg(name);
        ASSERT(arg);
        ASSERT(arg->boolean == true);
        arg->u.enabled = value;
}

#endif
