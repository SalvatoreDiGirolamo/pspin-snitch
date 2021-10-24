
// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef HOST
#include <handler.h>
#include <packets.h>
#else
#include <handler_profiler.h>
#endif

#ifndef NUM_INT_OP
#define NUM_INT_OP 0
#endif

volatile __attribute__((section(".l2_handler_data"))) uint8_t handler_mem[] = {0xde, 0xad, 0xbe, 0xef};

__handler__ void empty_ph(handler_args_t *args) 
{
    uint32_t *l2_ptr = (uint32_t*) (args->task->handler_mem);
    uint32_t *pkt_ptr = (uint32_t*) (args->task->pkt_mem);
    asm volatile("lw t1, 4(%0)" : : "r"(pkt_ptr));
    asm volatile("lw t2, 8(%0)" : : "r"(pkt_ptr));
    asm volatile("lw t3, 12(%0)" : : "r"(pkt_ptr));
    asm volatile("lw t4, 0(%0)" : : "r"(l2_ptr));
    asm volatile("mul t0, t1, t2");
    asm volatile("mul t0, t1, t2");
    asm volatile("mul t0, t1, t2");
    asm volatile("mul t2, t3, t4");
    asm volatile("fadd.s  fa5,fa5,fa4");
    asm volatile("fcvt.w.s a5,fa5,rtz");
    asm volatile("addi a5,a5,1");
    asm volatile("add t3, t0, t3"); 
    
#if (NUM_INT_OP > 0)
    volatile int xx = 0;
    int x = xx;
    for (int i=0; i<NUM_INT_OP; i++) {
        x = x*i;
    }
    xx = x;
#endif
}

void init_handlers(handler_fn * hh, handler_fn *ph, handler_fn *th, void **handler_mem_ptr)
{
    volatile handler_fn handlers[] = {NULL, empty_ph, NULL};
    *hh = handlers[0];
    *ph = handlers[1];
    *th = handlers[2];

    *handler_mem_ptr = (void*) handler_mem;
}

