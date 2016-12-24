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
#include <assert.h>

typedef struct {
  target_ulong start;
  target_ulong end;
  char* filename;
  FILE* file;
} vad_descriptor;

int before_block_exec(CPUState *env, TranslationBlock *tb);
int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
bool in_module(CPUState *env, TranslationBlock *tb);
bool seen_code(CPUState *env, TranslationBlock *tb);
vad_descriptor open_vad(char* filename);
void free_vad_descriptor_array(vad_descriptor* vads);
vad_descriptor* get_enclosing_vad_files(target_ulong address);


bool init_plugin(void *);
void uninit_plugin(void *);

int replay_round = 0;
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

vad_descriptor open_vad(char* filename) {
  // Structure of the filenames are:
  //  ProcName.Offset.start-end.dmp
  // So to extract the start and end, first we find the dash
  vad_descriptor vd;
  int dashIdx = 0;
  for(; filename[dashIdx] != '-' && filename[dashIdx] != '\0'; dashIdx++) {}

  if(filename[dashIdx] == '\0') {
    printf("Malformed VAD filename!  %s", filename);
    return vd;
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
  char* startBuff = calloc(startLen, sizeof(char)); char* endBuff = calloc(endLen, sizeof(char));

  strncpy(startBuff, filename + startIdx, startLen);
  strncpy(endBuff, filename + dashIdx + 1, endLen);

  target_ulong startAddr = strtoll(startBuff, NULL, 0);
  target_ulong endAddr = strtoll(endBuff, NULL, 0);

  free(startBuff);
  free(endBuff);

  vd.start = startAddr;
  vd.end = endAddr;
  vd.filename = filename;
  return vd;
}

vad_descriptor* get_enclosing_vad_files(target_ulong address) {
  DIR *dp;
  struct dirent *ep;

  dp = opendir("./vads/");
  if(dp == NULL) {
    printf("VADS directory not found!");
    return NULL;
  }
  int fileCount = 0;
  while((ep = readdir(dp))) {
    if(ep->d_type == DT_REG) {
      vad_descriptor vd = open_vad(ep->d_name);
      if( vd.start < address && address < vd.end ) {
        fileCount++;
      }
    }
  }

  if(fileCount == 0) {
    return NULL;
  }

  vad_descriptor* enclosing_vads = calloc(fileCount + 1, sizeof(vad_descriptor));

  rewinddir(dp);
  int idx = 0;
  while((ep = readdir(dp))) {
    if(ep->d_type == DT_REG) {
      vad_descriptor vd = open_vad(ep->d_name);
      if( vd.start < address && address < vd.end ) {
        enclosing_vads[idx] = vd;
        char path[100] = "./vads/"; // should be plenty...
        strcat(path + 7, vd.filename);
        enclosing_vads[idx].file = fopen(path, "rb");
        idx++;
      }
    }
  }

  return enclosing_vads;
}

void free_vad_descriptor_array(vad_descriptor* vads) {
  int idx;
  for(idx = 0; vads[idx].filename != NULL; idx++) {
    fclose(vads[idx].file);
  }
  free(vads);
}

// Check if we're inside code we've seen before
bool seen_code(CPUState *env, TranslationBlock *tb) {
  // Grab the memory for this basic block
  bool seen = false;

  // Find the files that contain this range
  vad_descriptor* vads = get_enclosing_vad_files(tb->pc);

  if(vads == NULL) {
    return false;
  }

  target_ulong bbStart = tb->pc;
  target_ulong bbSize  = tb->size;
  unsigned char *bbBuff = calloc(bbSize + 1, sizeof(char));
  unsigned char *fileBuff = calloc(bbSize + 1, sizeof(char));
  // Copy the instructions from this bb to a buffer
  //printf("Start: %#010llx Size: %#010llx", (unsigned long long) bbStart, (unsigned long long) bbSize);
  cpu_memory_rw_debug(env, bbStart, bbBuff, bbSize, 0);

  // For each of the files enclosing the program counter,
  int idx;
  for(idx = 0; vads[idx].filename != NULL; idx++) {
    assert(bbStart + bbSize < vads[idx].end);
    // Seek to the offset of the program counter
    FILE* vad_file = vads[idx].file;
    target_ulong offset = bbStart - vads[idx].start;
    fseek(vad_file, offset, SEEK_SET);
    int bytesRead = fread(fileBuff, bbSize, 1, vad_file);
    assert(bytesRead == 1);

    // and compare the bytes for bbSize
    int byteCounter;
    bool identical = true;
    for(byteCounter = 0; byteCounter < bbSize; byteCounter++) {
      if(fileBuff[byteCounter] != bbBuff[byteCounter]) {
        identical = false;
        break;
      }
    }
    // If we compared the whole loop, and the byte arrays were identical
    if(identical) {
      // We've seen this code before, so stop looking at the other VADs
      seen = true;
      break;
    }
  }

  free_vad_descriptor_array(vads);

  return seen;
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
    return 0;
  }

  printf("\tNew code found at PC: %#010llx!!\n", (unsigned long long)tb->pc);
  char out_file[100];
  sprintf(out_file, "./dumps/dump.raw.%d", replay_round);
  printf("Dumping memory to %s and aborting replay.\n", out_file);
  panda_memsavep(fopen(out_file, "wb"));
  done = true;
  rr_end_replay_requested = 1;

  // Print out a bit of our story
  FILE* story = fopen("story.txt", "a");
  target_ulong instrIdx = rr_get_guest_instr_count();
  fprintf(story, \
      "Ran until instruction %llu, executing basic block at %#010llx, which is not kernel, library, or previously seen code.\n", \
      (unsigned long long) instrIdx, \
      (unsigned long long) tb->pc);
  fclose(story);

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
  panda_arg_list *args = panda_get_args("unpack");
  replay_round = panda_parse_uint32(args, "round", 0);

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
