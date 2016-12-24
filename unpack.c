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
void on_process_exit(CPUState *env, OsiProc *proc);
bool in_module(CPUState *env, TranslationBlock *tb);
bool seen_code(CPUState *env, TranslationBlock *tb);
vad_descriptor open_vad(char* filename);
void free_vad_descriptor_array(vad_descriptor* vads);
vad_descriptor* get_enclosing_vad_files(target_ulong address);


bool init_plugin(void *);
void uninit_plugin(void *);

char* process_name;
int replay_round = 0;
int pid = 0;
bool first = true;
bool done = false;
bool monitoring = false;

// Once the suspicious process exits, we should take a memory dump and stop listening
void on_process_exit(CPUState *env, OsiProc *proc) {
  if(pid == 0) return; // We haven't gotten to our process yet 
  if(proc->pid != pid) return; // We don't care about anyone else

  // The malicious process is exiting, so take a memory dump and terminate the replay
  done = true;
  rr_end_replay_requested = 1;
  char out_file[100];
  sprintf(out_file, "./%s/dumps/dump.raw.%d", process_name, replay_round);
  printf("Dumping memory to %s one final time as the process exits and finishing replay.\n", out_file);
  FILE* outFile = fopen(out_file, "wb");
  panda_memsavep(outFile);
  fclose(outFile);

  // Print out a finished line!
  char story_fileName[100];
  sprintf(story_fileName, "./%s/story.txt", process_name);
  FILE* story = fopen(story_fileName, "a");
  fprintf(story, "Replay finished!\n");
  fclose(story);
}

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
  char* startBuff = calloc(startLen, sizeof(char));
  char* endBuff = calloc(endLen, sizeof(char));

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

  char dirPath[100];
  sprintf(dirPath, "./%s/vads/", process_name);
  dp = opendir(dirPath);
  if(dp == NULL) {
    printf("VADS directory not found!");
    return NULL;
  }
  int fileCount = 0;
  while((ep = readdir(dp))) {
    if(ep->d_name[0] != '.') { // d_type is always 0 for some reason, so just skip dot files / directories
      vad_descriptor vd = open_vad(ep->d_name);
      if( vd.start < address && address < vd.end ) {
        fileCount++;
      }
    }
  }

  if(fileCount == 0) {
    closedir(dp);
    return NULL;
  }

  vad_descriptor* enclosing_vads = calloc(fileCount + 1, sizeof(vad_descriptor));

  rewinddir(dp);
  int idx = 0;
  while((ep = readdir(dp))) {
    if(ep->d_name[0] != '.') {
      vad_descriptor vd = open_vad(ep->d_name);
      if( vd.start < address && address < vd.end ) {
        enclosing_vads[idx] = vd;
        char path[100]; // should be plenty...
        sprintf(path, "./%s/vads/%s", process_name, vd.filename);
        enclosing_vads[idx].file = fopen(path, "rb");
        idx++;
      }
    }
  }

  closedir(dp);

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
    printf("No enclosing VAD files!\n");
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
  free(bbBuff);
  free(fileBuff);

  return seen;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
  target_ulong instrIdx = rr_get_guest_instr_count();
  //if(instrIdx < 1517345636) return 0; // testing
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
  sprintf(out_file, "./%s/dumps/dump.raw.%d", process_name, replay_round);
  printf("Dumping memory to %s and aborting replay.\n", out_file);
  FILE* outFile = fopen(out_file, "wb");
  panda_memsavep(outFile);
  fclose(outFile);
  done = true;
  rr_end_replay_requested = 1;

  // Print out a bit of our story
  char story_fileName[100];
  sprintf(story_fileName, "./%s/story.txt", process_name);
  FILE* story = fopen(story_fileName, "a");
  float percentage = rr_get_percentage();
  fprintf(story, \
      "Ran until instruction %llu (%.2f%% through the replay), executing basic block at %#010llx, which is not kernel, library, or previously seen code.\n", \
      (unsigned long long) instrIdx, \
      percentage, \
      (unsigned long long) tb->pc);
  fclose(story);

  return 0;
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
  if(done) return 0;

  OsiProc *current = get_current_process(env);

  if(strcmp(current->name, process_name) == 0) {
    if(first) {
      first = false;
      pid = current->pid;
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
  process_name = panda_parse_string(args, "process", "cmd.exe");

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
  if(!done) {
    char out_fileName[100];
    sprintf(out_fileName, "./%s/dumps/dump.raw.%d", process_name, replay_round);
    printf("Dumping memory to %s one final time and finishing replay.\n", out_fileName);
    FILE* outFile = fopen(out_fileName, "wb");
    panda_memsavep(outFile);
    fclose(outFile);

    // Print out a finished line!
    char story_fileName[100];
    sprintf(story_fileName, "./%s/story.txt", process_name);
    FILE* story = fopen(story_fileName, "a");
    fprintf(story, "Replay finished!\n");
    fclose(story);
  }
  printf("\n\n");
    //fclose(plugin_log);
}
