#define __STDC_FORMAT_MACROS

#include "config.h"
#include "qemu-common.h"
#include "cpu.h"

#include "rr_log.h"
#include "panda_plugin.h"
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int before_block_exec(CPUState *env, TranslationBlock *tb);
int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
bool in_module(CPUState *env, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

bool done = false;
bool monitoring = false;
bool first = true;

// Check if we're inside a DLL/module
bool in_module(CPUState *env, TranslationBlock *tb) {
  OsiProc *current = get_current_process(env);
  OsiModules *ms = get_libraries(env, current);
  bool inside = false;
  if(ms != NULL) {
    int i;
    for(i = 0; i < ms->num; i++) {
      unsigned long long pc = tb->pc;
      unsigned long long start = ms->module[i].base;
      unsigned long long end = ms->module[i].base + ms->module[i].size;
      if(start < pc && pc < end) {
        inside = true;
        //printf("In Process!\n\tPC: %#010llx\n\t", pc);
        break;
      }
    }
  }

  free_osimodules(ms);
  free_osiproc(current);

  return inside;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
  if(!monitoring || done) return 0;

  // Ignore this BB if we're in the kernel or a DLL/Module
  if(panda_in_kernel(env)) {
    return 0;
  }
  if(in_module(env, tb)) {
    return 0;
  }

  printf("\tPC: %#010llx\n", (unsigned long long)tb->pc);
  printf("Dumping memory and aborting replay.\n");
  panda_memsavep(fopen("dump.raw", "wb"));
  //done = true;
  //rr_end_replay_requested = 1;

  return 0;
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
  if(done) return 0;

  OsiProc *current = get_current_process(env);

  char procName[9] = {0};
  strncpy(procName, current->name, 8);

  if(strcmp(procName, "b022e7cc") == 0) {
    if(first) {
      first = false;
      printf(" Process found!\n\tPID: %d\n", current->pid);
    }
    if(!monitoring) {
      // We're now on the correct process, so register a callback to listen to each block
      monitoring = true;
    }
  } else {
    if(monitoring) {
      monitoring = false;
    }
  }

  free_osiproc(current);

  return 0;
}

bool init_plugin(void *self) {
// Don't bother if we're not on x86
#ifdef TARGET_I386
  panda_cb pcb;

  pcb.before_block_exec = before_block_exec;
  panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
  pcb.after_PGD_write = vmi_pgd_changed;
  panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);


  if(!init_osi_api()) {
    printf("Failed to init osi!\n");
    return false;
  }

#endif

  //plugin_log = fopen("unpacks.txt", "w");
  //if(!plugin_log) return false;
  //else return true;
  return true;
}

void uninit_plugin(void *self) {
  printf("\n\n");
    //fclose(plugin_log);
}
