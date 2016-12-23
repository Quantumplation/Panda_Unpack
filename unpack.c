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
#include <sys/types.h>
#include <dirent.h>

int before_block_exec(CPUState *env, TranslationBlock *tb);
int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
bool in_module(CPUState *env, TranslationBlock *tb);
bool seen_code(CPUState *env, TranslationBlock *tb);
bool isEnclosing(char* filename, target_ulong address);
void free_file_array(FILE** files);
FILE** get_enclosing_vad_files(target_ulong address);

bool init_plugin(void *);
void uninit_plugin(void *);

bool first = true;
bool done = false;
bool monitoring = false;

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
        break;
      }
    }
  }

  free_osimodules(ms);
  free_osiproc(current);

  return inside;
}

bool isEnclosing(char* filename, target_ulong address) {
  // Structure of the filenames are:
  //  ProcName.Offset.start-end.dmp
  // So to extract the start and end, first we find the dash
  int dashIdx = 0;
  for(; filename[dashIdx] != '-' && filename[dashIdx] != '\0'; dashIdx++) {}

  if(filename[dashIdx] == '\0') {
    printf("Malformed VAD filename!  %s", filename);
    return false;
  }

  // Now, walk backwards to find the previous .
  int startIdx = dashIdx - 1;
  for(; filename[startIdx] != '.' && startIdx > 0; startIdx--) {}
  startIdx++; // Increment to remove the dot

  // and forwards to find the next .
  int endIdx = dashIdx + 1;
  for(; filename[endIdx] != '.' && filename[endIdx] != '\0'; endIdx++) {}


  // Now, slicing with [startIdx, dashIdx):
  //  start
  // and with (dashIdx, endIdx)
  //  end
  // (Pay attention to the boundaries there)
  int startLen = dashIdx - startIdx;
  int endLen = endIdx - dashIdx - 1;
  // Copy them to their own buffers and parse them
  char* startBuff = calloc(startLen, sizeof(char));
  char* endBuff = calloc(endLen, sizeof(char));

  strncpy(startBuff, filename + startIdx, startLen);
  strncpy(endBuff, filename + dashIdx + 1, endLen);

  target_ulong startAddr = strtoll(startBuff, NULL, 0);
  target_ulong endAddr = strtoll(endBuff, NULL, 0);

  free(startBuff);
  free(endBuff);

  return startAddr < address && address < endAddr;
}

FILE** get_enclosing_vad_files(target_ulong address) {
  DIR *dp;
  struct dirent *ep;

  dp = opendir("./vads/");
  if(dp == NULL) {
    printf("VADS directory not found!");
    return NULL;
  }
  int fileCount = 0;
  while((ep = readdir(dp))) {
    printf("Checking %s\n", ep->d_name);
    if(ep->d_type == DT_REG) {
      printf("\tchecking %s for enclosure\n", ep->d_name);
      if(isEnclosing(ep->d_name, address)) {
        printf("\t%s encloses %#010llx\n", ep->d_name, (unsigned long long) address);
        fileCount++;
      }
    }
  }

  FILE** files = calloc(fileCount + 1, sizeof(FILE*));

  return files;
}

void free_file_array(FILE** files) {
  printf("\tfreeing file array\n");
  int idx;
  for(idx = 0; files[idx] != NULL; idx++) {
    fclose(files[idx]);
  }
  free(files);
}

// Check if we're inside code we've seen before
bool seen_code(CPUState *env, TranslationBlock *tb) {
  // Grab the memory for this basic block
  //target_ulong bbStart = tb->pc;
  //target_ulong bbSize  = tb->size;
  //unsigned char *buf = calloc(bbSize, sizeof(char));
  // Copy the instructions from this bb to a buffer
  //cpu_memory_rw_debug(env, bbStart, buf, bbSize, 0);

  printf("\tgetting enclosing vad files\n");
  // Find the files that contain this range
  FILE** files = get_enclosing_vad_files(tb->pc);

  free_file_array(files);
  //free(buf);
  return false;
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
  if(seen_code(env, tb)) {
  }

  printf("\tPC: %#010llx\n", (unsigned long long)tb->pc);
  printf("Dumping memory and aborting replay.\n");
  panda_memsavep(fopen("dump.raw", "wb"));
  done = true;
  rr_end_replay_requested = 1;

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
      printf(" Process found!\n\tPID: %llu\n", (unsigned long long)current->pid);
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
