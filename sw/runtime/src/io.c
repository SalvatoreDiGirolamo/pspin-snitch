// Copyright 2020 ETH Zurich and University of Bologna.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>

void snrt_putchar(char character) 
{
    *(uint32_t*)(long)(0x1A104000) = character;
}

// Generator symbols with the proper names.
#define printf_ printf
#define sprintf_ sprintf
#define snprintf_ snprintf
#define vsnprintf_ vsnprintf
#define vprintf_ vprintf
#define _putchar snrt_putchar

// Include the vendorized tiny printf implementation.
#define _PRINTF_H_
#define PRINTF_DISABLE_SUPPORT_FLOAT
#include <stdarg.h>
#include <stddef.h>

#include "../vendor/printf.c"
