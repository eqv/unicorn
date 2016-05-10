/*
   Executable memory regions demo / unit test

   Copyright(c) 2015 Chris Eagle

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <unicorn/unicorn.h>
#include "./dump_meta.h"

static int instrs_executed = 1;

uint32_t rand_32(){
  return (uint32_t)(rand());
}

uint64_t rand_64(){
  uint64_t rnd2 = rand_32();
  return rand_32()^(rnd2 << 32);
}

void map_page(uc_engine *uc, uint64_t addr, uint64_t size){
    unsigned char buffer[4096];
    uint64_t base_addr = addr - (addr%4096);
    uint64_t upper_addr = (addr + size) - (addr+size)%4096 + 4096;
    uint64_t map_size = upper_addr-base_addr;
    uc_mem_map(uc, base_addr, map_size, UC_PROT_READ|UC_PROT_WRITE|UC_PROT_EXEC);
    uint64_t iter_addr;
    for(iter_addr = base_addr; iter_addr < upper_addr; iter_addr+= 4096){
      int i;
      for(i = 0; i<4096; i++){
        buffer[i]=rand();
      }
      uc_mem_write(uc, iter_addr, buffer, 4096);
    }
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data)
{
    printf("execute %lx\n", addr);
    instrs_executed++;
    if(instrs_executed > 1000){
      printf("terminated trace due to length\n");
      if (uc_emu_stop(uc) != UC_ERR_OK) { _exit(-1); }
    }

    if ( rand_64()%2 == 0){
      char buf[4096];
      uc_mem_read(uc, rand_64()&0xfffff, &buf, 4096);
    }

    if(rand_64()%10 == 0){
      map_page(uc, rand_64()&0xff000, 4096);
    }

    if(rand_64()%10 == 0){
      uc_mem_unmap(uc, rand_64()&0xff000,4096);
    }
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data)
{
    map_page(uc, addr, size);
    return true;
}

uc_engine* setup_emulator()  {

    uc_engine *uc;
    uc_hook trace1, trace2;
    uc_err err;

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) { return NULL; }

    uint64_t page_aligned_map_len = map_len - (map_len%4096) + 4096;
    if (uc_mem_map(uc, map_offset, page_aligned_map_len, UC_PROT_READ | UC_PROT_EXEC) != UC_ERR_OK){ return NULL; }
    uc_mem_write(uc, map_offset, map_data, map_len);

    uint64_t stack_ptr = rand_64();

    // Setup stack pointer
    uc_reg_write(uc, UC_X86_REG_ESP, &stack_ptr);

    if (uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, (uint64_t)1, (uint64_t)0) != UC_ERR_OK) { return NULL; }

    // intercept invalid memory events
    if (uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid, NULL) != UC_ERR_OK) { return NULL; }

    return uc;
}

void run_test(int seed){
    srand(seed);

    uc_engine *uc;
    uc_err err;

    uc = setup_emulator();
    if(uc == NULL){printf("failed to setup emultator\n");return;}


    int i;

    for(i = 0; i<100; i++){
      instrs_executed = 0;
      uint64_t addr = entry_points[rand_64()%entry_points_len];
      printf("run iter %d at %lx\n",i,addr);
      err = uc_emu_start(uc, addr, 0xFFFFFFFFFFFFFFFF, 0, 0);
    }

    if (err != UC_ERR_OK) { return; } 

    if (uc_close(uc) != UC_ERR_OK) { return; }

    return;
}

int main(int argc, char **argv, char **envp) {
  int i;
  for(i =0;i< 10; i++){
    printf("Run testcase %d\n", i);
    run_test(i);
  }
}
