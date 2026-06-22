#ifndef API_H
#define API_H

#include <stdint.h>

#define NAME_SIZE 64U

typedef struct {
  uint32_t Pid;
  uint32_t Reserved;
  uint64_t Eprocess;
  uint64_t Cr3;
  uint64_t ImageBase;
  char Name[NAME_SIZE];
} PROCESS_INFO;

typedef struct {
  uint32_t Pid;
  uint32_t Reserved;
  uint64_t Base;
  uint64_t Size;
  uint64_t Cr3;
  char Name[NAME_SIZE];
} MODULE_INFO;

typedef struct {
  uint64_t Address;
  uint32_t Size;
  uint32_t BufferOffset;
  uint32_t Status;
} READV_ENTRY;

#define EXEC_OP_MOV_IMM 1U
#define EXEC_OP_READ_U8 2U
#define EXEC_OP_READ_U16 3U
#define EXEC_OP_READ_U32 4U
#define EXEC_OP_READ_U64 5U
#define EXEC_OP_ADD 6U
#define EXEC_OP_AND 7U
#define EXEC_OP_SHR 8U
#define EXEC_OP_MUL 9U
#define EXEC_OP_OUT 10U
#define EXEC_OP_READ_OUT 11U
#define EXEC_OP_LEA 12U

#define EXEC_FLAG_OPTIONAL 0x00000001U
#define EXEC_FLAG_BREAK_ON_ERROR 0x00000002U
#define EXEC_FLAG_SKIP_IF_ZERO 0x00000004U

typedef struct {
  uint8_t Op;
  uint8_t Dst;
  uint8_t Src;
  uint8_t Aux;
  uint32_t Reserved0;
  uint64_t Imm;
  uint32_t Size;
  uint32_t OutOffset;
  uint32_t Status;
  uint32_t Flags;
} EXEC_OP;

typedef int (*DUMP_CALLBACK)(uint64_t Address, const void *Data,
                             uint32_t Size, void *Context);

int Init(void);
void Close(void);
int Ping(void);
int FindProcessByPid(uint32_t Pid, PROCESS_INFO *Process);
int FindProcessByName(const char *Name, PROCESS_INFO *Process);
int TranslateVirt(uint32_t Pid, uint64_t Va, uint64_t *Pa);
int ReadPhys(uint64_t Address, void *Buffer, uint32_t Size);
int WritePhys(uint64_t Address, const void *Buffer, uint32_t Size);
int ReadVirt(uint32_t Pid, uint64_t Address, void *Buffer, uint32_t Size);
int ReadVirtBatch(uint32_t Pid, READV_ENTRY *Entries, uint32_t Count,
                  void *Buffer, uint32_t BufferSize);
int ReadExec(uint32_t Pid, EXEC_OP *Ops, uint32_t OpCount, void *Output,
             uint32_t OutputSize);
int WriteVirt(uint32_t Pid, uint64_t Address, const void *Buffer,
              uint32_t Size);
int FindModule(const PROCESS_INFO *Process, const char *Name,
               MODULE_INFO *Module);
int FindKernelModule(const char *Name, MODULE_INFO *Module);
int FindExport(const MODULE_INFO *Module, const char *Name,
               uint64_t *Address);
int Dump(const MODULE_INFO *Module, DUMP_CALLBACK Callback, void *Context);

#endif
