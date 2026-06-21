#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "Api.h"

#define WMIGUID_EXECUTE 0x0010
#define WMI_METHOD_ID 1U
#define REQUEST_SIZE 4096U
#define RESPONSE_SIZE 4096U
#define REQUEST_DATA_SIZE 4048U
#define RESPONSE_DATA_SIZE 4060U
#define REQ_MAGIC 0x5145524D4D5355ULL
#define RESP_MAGIC 0x5345524D4D5355ULL
#define STATUS_OK 0U

#define CMD_PING 1U
#define CMD_READ_PHYS 2U
#define CMD_WRITE_PHYS 3U
#define CMD_TRANSLATE_VIRT 4U
#define CMD_READ_VIRT 5U
#define CMD_WRITE_VIRT 6U
#define CMD_FIND_PROCESS_PID 7U
#define CMD_FIND_PROCESS_NAME 8U
#define CMD_FIND_MODULE 9U
#define CMD_FIND_KERNEL_MODULE 10U
#define CMD_FIND_EXPORT 11U
#define CMD_DIAG 12U
#define CMD_ATTACH_RING 13U
#define CMD_RUN_RING 14U

typedef ULONG(WINAPI *WMI_OPEN_BLOCK)(GUID *Guid, DWORD DesiredAccess,
                                      HANDLE *DataBlockHandle);
typedef ULONG(WINAPI *WMI_EXECUTE_METHOD_W)(HANDLE DataBlockHandle,
                                            const wchar_t *InstanceName,
                                            ULONG MethodId,
                                            ULONG InBufferSize,
                                            void *InBuffer,
                                            ULONG *OutBufferSize,
                                            void *OutBuffer);
typedef ULONG(WINAPI *WMI_CLOSE_BLOCK)(HANDLE DataBlockHandle);

#pragma pack(push, 1)
typedef struct {
  uint64_t Magic;
  uint32_t Command;
  uint32_t DataSize;
  uint64_t Sequence;
  uint64_t Arg1;
  uint64_t Arg2;
  uint64_t Arg3;
  uint8_t Data[1];
} REQUEST;

typedef struct {
  uint64_t Magic;
  uint32_t Status;
  uint32_t Command;
  uint32_t DataSize;
  uint64_t Sequence;
  uint64_t Result;
  uint8_t Data[RESPONSE_DATA_SIZE];
} RESPONSE;

#pragma pack(pop)

typedef struct {
  HMODULE Advapi;
  WMI_OPEN_BLOCK OpenBlock;
  WMI_EXECUTE_METHOD_W ExecuteMethod;
  WMI_CLOSE_BLOCK CloseBlock;
  HANDLE Block;
  const wchar_t **Instances;
  uint64_t Sequence;
} STATE;

#define DIAG_MAX_CPUS 12U
#define DIAG_MAX_PROBES 8U

typedef struct {
  uint64_t Lstar;
  uint64_t CurrentCr3;
  uint64_t ProbeCr3;
  uint64_t KernelCr3;
  uint64_t KernelBase;
  uint64_t SystemProcess;
  uint64_t PsLoadedModuleList;
  uint32_t NumberOfCpus;
  uint32_t SmmCpuPresent;
  uint64_t SavedCr3[DIAG_MAX_CPUS];
  uint32_t SavedStatus[DIAG_MAX_CPUS];
  uint64_t ProbeBase[DIAG_MAX_PROBES];
  uint32_t ProbeStatus[DIAG_MAX_PROBES];
  uint32_t ProbeValue[DIAG_MAX_PROBES];
  uint32_t InitKernelStatus;
  uint32_t ListLayoutStatus;
  uint32_t Cr3OffsetStatus;
  uint32_t Reserved;
} DIAG_INFO;

#define RING_MAGIC 0x31474E49524D4D53ULL
#define RING_VERSION 1U
#define RING_OP_BENCH_READ 1U

typedef struct {
  uint64_t Magic;
  uint32_t Version;
  uint32_t HeaderSize;
  uint32_t Op;
  uint32_t Status;
  uint64_t Sequence;
  uint32_t TargetPid;
  uint32_t Size;
  uint64_t TargetVa;
  uint64_t Count;
  uint64_t Completed;
  uint64_t Checksum;
  uint64_t TscStart;
  uint64_t TscEnd;
} RING_HEADER;

static GUID gMemGuid = {
    0xa0c9f8de,
    0x0b71,
    0x42a8,
    {0xb9, 0x67, 0xe5, 0x38, 0xea, 0xcb, 0x6f, 0x21}};
static const wchar_t *gMemInstances[] = {
    L"ACPI\\PNP0C14\\Mem_0",
    L"ACPI\\PNP0C14\\SMMM_0",
    L"ACPI\\PNP0C14\\0_0",
    L"",
    NULL};

static STATE g;

#ifndef API_ONLY
static int gVerbose;
#endif

static void CloseRaw(void) {
  if (g.CloseBlock != NULL && g.Block != NULL) {
    g.CloseBlock(g.Block);
  }
  if (g.Advapi != NULL) {
    FreeLibrary(g.Advapi);
  }
  ZeroMemory(&g, sizeof(g));
}

static int OpenRaw(GUID *Guid, const wchar_t **Instances) {
  ULONG Status;

  CloseRaw();
  g.Advapi = LoadLibraryW(L"Advapi32.dll");
  if (g.Advapi == NULL) {
#ifndef API_ONLY
    if (gVerbose) {
      fwprintf(stderr, L"LoadLibraryW(Advapi32.dll) failed: 0x%08lX\n",
               GetLastError());
    }
#endif
    return 0;
  }
  g.OpenBlock = (WMI_OPEN_BLOCK)GetProcAddress(g.Advapi, "WmiOpenBlock");
  g.ExecuteMethod =
      (WMI_EXECUTE_METHOD_W)GetProcAddress(g.Advapi, "WmiExecuteMethodW");
  g.CloseBlock = (WMI_CLOSE_BLOCK)GetProcAddress(g.Advapi, "WmiCloseBlock");
  if (g.OpenBlock == NULL || g.ExecuteMethod == NULL ||
      g.CloseBlock == NULL) {
#ifndef API_ONLY
    if (gVerbose) {
      fwprintf(stderr, L"WMI entrypoint lookup failed\n");
    }
#endif
    CloseRaw();
    return 0;
  }
  Status = g.OpenBlock(Guid, WMIGUID_EXECUTE, &g.Block);
  if (Status != ERROR_SUCCESS) {
#ifndef API_ONLY
    if (gVerbose) {
      fwprintf(stderr, L"WmiOpenBlock failed: 0x%08lX\n", Status);
    }
#endif
    CloseRaw();
    return 0;
  }
  g.Instances = Instances;
  g.Sequence = GetTickCount64();
  return 1;
}

int Init(void) {
  return OpenRaw(&gMemGuid, gMemInstances);
}

void Close(void) {
  CloseRaw();
}

static void InitRequest(REQUEST *Request, uint32_t Command) {
  ZeroMemory(Request, REQUEST_SIZE);
  Request->Magic = REQ_MAGIC;
  Request->Command = Command;
  Request->Sequence = ++g.Sequence;
}

static int ExecuteStandalone(REQUEST *Request, RESPONSE *Response) {
  uint8_t Out[RESPONSE_SIZE];
  ULONG OutSize;
  ULONG Status;

  for (size_t Index = 0; g.Instances[Index] != NULL; Index++) {
    ZeroMemory(Out, sizeof(Out));
    OutSize = sizeof(Out);
    Status = g.ExecuteMethod(g.Block, g.Instances[Index], WMI_METHOD_ID,
                             REQUEST_SIZE, Request, &OutSize, Out);
#ifndef API_ONLY
    if (gVerbose) {
      fwprintf(stderr, L"instance=%ls status=0x%08lX out=%lu\n",
               g.Instances[Index], Status, OutSize);
    }
#endif
    if (Status == ERROR_SUCCESS) {
      CopyMemory(Response, Out, sizeof(*Response));
#ifndef API_ONLY
      if (gVerbose) {
        fwprintf(stderr,
                 L"  magic=0x%016llX smm_status=0x%08X command=%u result=0x%016llX sequence=%llu\n",
                 (unsigned long long)Response->Magic, Response->Status,
                 Response->Command, (unsigned long long)Response->Result,
                 (unsigned long long)Response->Sequence);
      }
#endif
      return Response->Magic == RESP_MAGIC;
    }
  }
  return 0;
}

static int Send(REQUEST *Request, RESPONSE *Response) {
  if (g.Block == NULL) {
    return 0;
  }
  ZeroMemory(Response, sizeof(*Response));
  return ExecuteStandalone(Request, Response);
}

int Ping(void) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;

  InitRequest(Request, CMD_PING);
  return Send(Request, &Response) && Response.Status == STATUS_OK;
}

int FindProcessByPid(uint32_t Pid, PROCESS_INFO *Process) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;

  InitRequest(Request, CMD_FIND_PROCESS_PID);
  Request->Arg1 = Pid;
  if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
      Response.DataSize < sizeof(*Process)) {
    return 0;
  }
  CopyMemory(Process, Response.Data, sizeof(*Process));
  return 1;
}

int FindProcessByName(const char *Name, PROCESS_INFO *Process) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  size_t Size = strlen(Name) + 1;

  if (Size > REQUEST_DATA_SIZE) {
    return 0;
  }
  InitRequest(Request, CMD_FIND_PROCESS_NAME);
  Request->DataSize = (uint32_t)Size;
  CopyMemory(Request->Data, Name, Size);
  if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
      Response.DataSize < sizeof(*Process)) {
    return 0;
  }
  CopyMemory(Process, Response.Data, sizeof(*Process));
  return 1;
}

int TranslateVirt(uint32_t Pid, uint64_t Va, uint64_t *Pa) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;

  InitRequest(Request, CMD_TRANSLATE_VIRT);
  Request->Arg1 = Pid;
  Request->Arg2 = Va;
  if (!Send(Request, &Response) || Response.Status != STATUS_OK) {
    return 0;
  }
  *Pa = Response.Result;
  return 1;
}

int ReadPhys(uint64_t Address, void *Buffer, uint32_t Size) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  uint32_t Done = 0;

  while (Done < Size) {
    uint32_t Chunk = Size - Done;
    if (Chunk > RESPONSE_DATA_SIZE) {
      Chunk = RESPONSE_DATA_SIZE;
    }
    InitRequest(Request, CMD_READ_PHYS);
    Request->Arg1 = Address + Done;
    Request->Arg2 = Chunk;
    if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
        Response.DataSize != Chunk) {
      return 0;
    }
    CopyMemory((uint8_t *)Buffer + Done, Response.Data, Chunk);
    Done += Chunk;
  }
  return 1;
}

int WritePhys(uint64_t Address, const void *Buffer, uint32_t Size) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  uint32_t Done = 0;

  while (Done < Size) {
    uint32_t Chunk = Size - Done;
    if (Chunk > REQUEST_DATA_SIZE) {
      Chunk = REQUEST_DATA_SIZE;
    }
    InitRequest(Request, CMD_WRITE_PHYS);
    Request->Arg1 = Address + Done;
    Request->DataSize = Chunk;
    CopyMemory(Request->Data, (const uint8_t *)Buffer + Done, Chunk);
    if (!Send(Request, &Response) || Response.Status != STATUS_OK) {
      return 0;
    }
    Done += Chunk;
  }
  return 1;
}

int ReadVirt(uint32_t Pid, uint64_t Address, void *Buffer, uint32_t Size) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  uint32_t Done = 0;

  while (Done < Size) {
    uint32_t Chunk = Size - Done;
    if (Chunk > RESPONSE_DATA_SIZE) {
      Chunk = RESPONSE_DATA_SIZE;
    }
    InitRequest(Request, CMD_READ_VIRT);
    Request->Arg1 = Pid;
    Request->Arg2 = Address + Done;
    Request->Arg3 = Chunk;
    if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
        Response.DataSize != Chunk) {
      return 0;
    }
    CopyMemory((uint8_t *)Buffer + Done, Response.Data, Chunk);
    Done += Chunk;
  }
  return 1;
}

int WriteVirt(uint32_t Pid, uint64_t Address, const void *Buffer,
              uint32_t Size) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  uint32_t Done = 0;

  while (Done < Size) {
    uint32_t Chunk = Size - Done;
    if (Chunk > REQUEST_DATA_SIZE) {
      Chunk = REQUEST_DATA_SIZE;
    }
    InitRequest(Request, CMD_WRITE_VIRT);
    Request->Arg1 = Pid;
    Request->Arg2 = Address + Done;
    Request->DataSize = Chunk;
    CopyMemory(Request->Data, (const uint8_t *)Buffer + Done, Chunk);
    if (!Send(Request, &Response) || Response.Status != STATUS_OK) {
      return 0;
    }
    Done += Chunk;
  }
  return 1;
}

int FindModule(const PROCESS_INFO *Process, const char *Name,
               MODULE_INFO *Module) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  size_t Size = strlen(Name) + 1;

  if (Size > REQUEST_DATA_SIZE) {
    return 0;
  }
  InitRequest(Request, CMD_FIND_MODULE);
  Request->Arg1 = Process->Pid;
  Request->DataSize = (uint32_t)Size;
  CopyMemory(Request->Data, Name, Size);
  if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
      Response.DataSize < sizeof(*Module)) {
    return 0;
  }
  CopyMemory(Module, Response.Data, sizeof(*Module));
  return 1;
}

int FindKernelModule(const char *Name, MODULE_INFO *Module) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  size_t Size = strlen(Name) + 1;

  if (Size > REQUEST_DATA_SIZE) {
    return 0;
  }
  InitRequest(Request, CMD_FIND_KERNEL_MODULE);
  Request->DataSize = (uint32_t)Size;
  CopyMemory(Request->Data, Name, Size);
  if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
      Response.DataSize < sizeof(*Module)) {
    return 0;
  }
  CopyMemory(Module, Response.Data, sizeof(*Module));
  return 1;
}

int FindExport(const MODULE_INFO *Module, const char *Name,
               uint64_t *Address) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;
  size_t NameSize = strlen(Name) + 1;
  uint32_t Size = (uint32_t)(sizeof(*Module) + NameSize);

  if (Size > REQUEST_DATA_SIZE) {
    return 0;
  }
  InitRequest(Request, CMD_FIND_EXPORT);
  Request->DataSize = Size;
  CopyMemory(Request->Data, Module, sizeof(*Module));
  CopyMemory(Request->Data + sizeof(*Module), Name, NameSize);
  if (!Send(Request, &Response) || Response.Status != STATUS_OK) {
    return 0;
  }
  *Address = Response.Result;
  return 1;
}

static int Diag(DIAG_INFO *Info) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;

  InitRequest(Request, CMD_DIAG);
  if (!Send(Request, &Response) || Response.Status != STATUS_OK ||
      Response.DataSize < sizeof(*Info)) {
    return 0;
  }
  CopyMemory(Info, Response.Data, sizeof(*Info));
  return 1;
}

static int AttachRing(uint32_t Pid, uint64_t RingVa, uint64_t RingSize) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;

  InitRequest(Request, CMD_ATTACH_RING);
  Request->Arg1 = Pid;
  Request->Arg2 = RingVa;
  Request->Arg3 = RingSize;
  return Send(Request, &Response) && Response.Status == STATUS_OK;
}

static int RunRing(void) {
  uint8_t In[REQUEST_SIZE];
  REQUEST *Request = (REQUEST *)In;
  RESPONSE Response;

  InitRequest(Request, CMD_RUN_RING);
  return Send(Request, &Response) && Response.Status == STATUS_OK;
}

int Dump(const MODULE_INFO *Module, DUMP_CALLBACK Callback, void *Context) {
  uint8_t Buffer[RESPONSE_DATA_SIZE];
  uint64_t Done = 0;

  if (Module == NULL || Module->Pid == 0 || Module->Base == 0 ||
      Module->Size == 0) {
    return 0;
  }
  while (Done < Module->Size) {
    uint64_t Address = Module->Base + Done;
    uint32_t Chunk = (uint32_t)(Module->Size - Done);
    if (Chunk > sizeof(Buffer)) {
      Chunk = sizeof(Buffer);
    }
    if (Chunk > 0x1000U - (uint32_t)(Address & 0xFFFU)) {
      Chunk = 0x1000U - (uint32_t)(Address & 0xFFFU);
    }
    if (!ReadVirt(Module->Pid, Address, Buffer, Chunk)) {
      ZeroMemory(Buffer, Chunk);
    }
    if (Callback != NULL && !Callback(Address, Buffer, Chunk, Context)) {
      return 0;
    }
    Done += Chunk;
  }
  return 1;
}

#ifndef API_ONLY
typedef struct {
  HANDLE File;
  uint64_t Written;
} DUMP_CONTEXT_EX;

static void Usage(void) {
  printf("Usage:\n");
  printf("  Client.exe [-v] ping\n");
  printf("  Client.exe [-v] diag\n");
  printf("  Client.exe [-v] findpid <pid>\n");
  printf("  Client.exe [-v] findproc <name.exe>\n");
  printf("  Client.exe [-v] kernel <module.sys|ntoskrnl.exe>\n");
  printf("  Client.exe [-v] module <pid> <module.dll>\n");
  printf("  Client.exe [-v] export <pid> <module.dll> <export>\n");
  printf("  Client.exe [-v] kexport <module.sys|ntoskrnl.exe> <export>\n");
  printf("  Client.exe [-v] translate <pid> <va>\n");
  printf("  Client.exe [-v] readphys <pa> <size> [out.bin]\n");
  printf("  Client.exe [-v] readvirt <pid> <va> <size> [out.bin]\n");
  printf("  Client.exe [-v] benchphys <pa> [count=1000000] [size=8]\n");
  printf("  Client.exe [-v] benchread <pid> <va> [count=1000000] [size=8]\n");
  printf("  Client.exe [-v] ringbench <pid> <va> [count=1000000] [size=8] [ring_kb=64]\n");
  printf("  Client.exe [-v] writephys <pa> <hex-bytes|@file>\n");
  printf("  Client.exe [-v] writevirt <pid> <va> <hex-bytes|@file>\n");
  printf("  Client.exe [-v] dump <pid> <module.dll> <out.bin>\n");
  printf("  Client.exe [-v] dumpkernel <module.sys|ntoskrnl.exe> <out.bin>\n");
}

static const char *EfiStatusName(uint32_t Status) {
  switch (Status) {
  case 0:
    return "EFI_SUCCESS";
  case 2:
    return "EFI_INVALID_PARAMETER";
  case 3:
    return "EFI_UNSUPPORTED";
  case 9:
    return "EFI_OUT_OF_RESOURCES";
  case 14:
    return "EFI_NOT_FOUND";
  default:
    return "EFI_STATUS";
  }
}

static int ParseU64(const wchar_t *Text, uint64_t *Value) {
  wchar_t *End = NULL;
  unsigned long long Parsed;
  if (Text == NULL || *Text == 0 || Value == NULL) {
    return 0;
  }
  Parsed = _wcstoui64(Text, &End, 0);
  if (End == Text || End == NULL || *End != 0) {
    return 0;
  }
  *Value = (uint64_t)Parsed;
  return 1;
}

static int WideToAscii(const wchar_t *Input, char *Output, size_t OutputSize) {
  int Count;
  if (Input == NULL || Output == NULL || OutputSize == 0) {
    return 0;
  }
  Count = WideCharToMultiByte(CP_ACP, 0, Input, -1, Output,
                              (int)OutputSize, NULL, NULL);
  if (Count <= 0) {
    Output[0] = 0;
    return 0;
  }
  Output[OutputSize - 1] = 0;
  return 1;
}

static void PrintProcess(const PROCESS_INFO *Process) {
  printf("pid=%u eprocess=0x%llx cr3=0x%llx image=0x%llx name=%s\n",
         Process->Pid, (unsigned long long)Process->Eprocess,
         (unsigned long long)Process->Cr3,
         (unsigned long long)Process->ImageBase, Process->Name);
}

static void PrintModule(const MODULE_INFO *Module) {
  printf("pid=%u base=0x%llx size=0x%llx cr3=0x%llx name=%s\n",
         Module->Pid, (unsigned long long)Module->Base,
         (unsigned long long)Module->Size, (unsigned long long)Module->Cr3,
         Module->Name);
}

static void PrintDiag(const DIAG_INFO *Info) {
  uint32_t Count = Info->NumberOfCpus;
  if (Count > DIAG_MAX_CPUS) {
    Count = DIAG_MAX_CPUS;
  }
  printf("lstar=0x%llx current_cr3=0x%llx probe_cr3=0x%llx\n",
         (unsigned long long)Info->Lstar,
         (unsigned long long)Info->CurrentCr3,
         (unsigned long long)Info->ProbeCr3);
  printf("kernel_cr3=0x%llx kernel_base=0x%llx system=0x%llx module_list=0x%llx\n",
         (unsigned long long)Info->KernelCr3,
         (unsigned long long)Info->KernelBase,
         (unsigned long long)Info->SystemProcess,
         (unsigned long long)Info->PsLoadedModuleList);
  printf("cpus=%u smm_cpu=%u init=%s(0x%08x) list=%s(0x%08x) cr3off=%s(0x%08x)\n",
         Info->NumberOfCpus, Info->SmmCpuPresent,
         EfiStatusName(Info->InitKernelStatus), Info->InitKernelStatus,
         EfiStatusName(Info->ListLayoutStatus), Info->ListLayoutStatus,
         EfiStatusName(Info->Cr3OffsetStatus), Info->Cr3OffsetStatus);
  for (uint32_t Index = 0; Index < Count; Index++) {
    printf("saved_cr3[%02u]=0x%llx status=%s(0x%08x)\n", Index,
           (unsigned long long)Info->SavedCr3[Index],
           EfiStatusName(Info->SavedStatus[Index]),
           Info->SavedStatus[Index]);
  }
  for (uint32_t Index = 0; Index < DIAG_MAX_PROBES; Index++) {
    if (Info->ProbeBase[Index] == 0 && Info->ProbeStatus[Index] == 0 &&
        Info->ProbeValue[Index] == 0) {
      continue;
    }
    printf("probe[%u] base=0x%llx status=%s(0x%08x) value=0x%04x\n", Index,
           (unsigned long long)Info->ProbeBase[Index],
           EfiStatusName(Info->ProbeStatus[Index]),
           Info->ProbeStatus[Index], Info->ProbeValue[Index] & 0xFFFFU);
  }
}

static void HexDump(uint64_t Base, const uint8_t *Data, uint32_t Size) {
  uint32_t Offset = 0;
  while (Offset < Size) {
    uint32_t Count = Size - Offset;
    if (Count > 16) {
      Count = 16;
    }
    printf("%016llx  ", (unsigned long long)(Base + Offset));
    for (uint32_t Index = 0; Index < 16; Index++) {
      if (Index < Count) {
        printf("%02X ", Data[Offset + Index]);
      } else {
        printf("   ");
      }
    }
    printf(" ");
    for (uint32_t Index = 0; Index < Count; Index++) {
      unsigned char Ch = Data[Offset + Index];
      printf("%c", (Ch >= 0x20 && Ch <= 0x7E) ? Ch : '.');
    }
    printf("\n");
    Offset += Count;
  }
}

static int WriteFileAll(const wchar_t *Path, const void *Data, uint32_t Size) {
  HANDLE File;
  DWORD Done;
  File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (File == INVALID_HANDLE_VALUE) {
    wprintf(L"open output failed: %ls error=0x%08lX\n", Path, GetLastError());
    return 0;
  }
  if (!WriteFile(File, Data, Size, &Done, NULL) || Done != Size) {
    printf("write output failed error=0x%08lX\n", GetLastError());
    CloseHandle(File);
    return 0;
  }
  CloseHandle(File);
  return 1;
}

static int ReadFileAll(const wchar_t *Path, uint8_t **Data, uint32_t *Size) {
  HANDLE File;
  LARGE_INTEGER FileSize;
  DWORD Done;
  uint8_t *Buffer;
  File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, NULL);
  if (File == INVALID_HANDLE_VALUE) {
    wprintf(L"open input failed: %ls error=0x%08lX\n", Path, GetLastError());
    return 0;
  }
  if (!GetFileSizeEx(File, &FileSize) || FileSize.QuadPart <= 0 ||
      FileSize.QuadPart > 16 * 1024 * 1024) {
    printf("input size rejected\n");
    CloseHandle(File);
    return 0;
  }
  Buffer = (uint8_t *)malloc((size_t)FileSize.QuadPart);
  if (Buffer == NULL) {
    CloseHandle(File);
    return 0;
  }
  if (!ReadFile(File, Buffer, (DWORD)FileSize.QuadPart, &Done, NULL) ||
      Done != (DWORD)FileSize.QuadPart) {
    printf("read input failed error=0x%08lX\n", GetLastError());
    free(Buffer);
    CloseHandle(File);
    return 0;
  }
  CloseHandle(File);
  *Data = Buffer;
  *Size = (uint32_t)FileSize.QuadPart;
  return 1;
}

static int HexValue(wchar_t Ch) {
  if (Ch >= L'0' && Ch <= L'9') {
    return (int)(Ch - L'0');
  }
  if (Ch >= L'a' && Ch <= L'f') {
    return (int)(Ch - L'a' + 10);
  }
  if (Ch >= L'A' && Ch <= L'F') {
    return (int)(Ch - L'A' + 10);
  }
  return -1;
}

static int ParseBytesArg(const wchar_t *Arg, uint8_t **Data, uint32_t *Size) {
  uint32_t HexChars = 0;
  uint32_t OutIndex = 0;
  uint8_t *Buffer;
  int High = -1;

  if (Arg == NULL || Data == NULL || Size == NULL) {
    return 0;
  }
  if (Arg[0] == L'@') {
    return ReadFileAll(Arg + 1, Data, Size);
  }
  for (const wchar_t *Ptr = Arg; *Ptr != 0; Ptr++) {
    if (HexValue(*Ptr) >= 0) {
      HexChars++;
    } else if (*Ptr == L',' || *Ptr == L':' || *Ptr == L'-' ||
               *Ptr == L' ' || *Ptr == L'\t') {
      continue;
    } else {
      return 0;
    }
  }
  if (HexChars == 0 || (HexChars & 1) != 0) {
    return 0;
  }
  Buffer = (uint8_t *)malloc(HexChars / 2);
  if (Buffer == NULL) {
    return 0;
  }
  for (const wchar_t *Ptr = Arg; *Ptr != 0; Ptr++) {
    int Value = HexValue(*Ptr);
    if (Value < 0) {
      continue;
    }
    if (High < 0) {
      High = Value;
    } else {
      Buffer[OutIndex++] = (uint8_t)((High << 4) | Value);
      High = -1;
    }
  }
  *Data = Buffer;
  *Size = OutIndex;
  return 1;
}

static int OpenApi(void) {
  if (!Init()) {
    printf("Init failed\n");
    return 0;
  }
  return 1;
}

static int DumpCallback(uint64_t Address, const void *Data, uint32_t Size,
                        void *Context) {
  DUMP_CONTEXT_EX *Dump = (DUMP_CONTEXT_EX *)Context;
  DWORD Done;
  (void)Address;
  if (Dump == NULL || Dump->File == INVALID_HANDLE_VALUE) {
    return 0;
  }
  if (!WriteFile(Dump->File, Data, Size, &Done, NULL) || Done != Size) {
    return 0;
  }
  Dump->Written += Size;
  return 1;
}

static int DumpModuleToFile(const MODULE_INFO *Module, const wchar_t *Path) {
  DUMP_CONTEXT_EX Context;
  int Ok;
  Context.Written = 0;
  Context.File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
  if (Context.File == INVALID_HANDLE_VALUE) {
    wprintf(L"open output failed: %ls error=0x%08lX\n", Path, GetLastError());
    return 0;
  }
  Ok = Dump(Module, DumpCallback, &Context);
  CloseHandle(Context.File);
  printf("dumped=0x%llx\n", (unsigned long long)Context.Written);
  return Ok;
}

static int RunReadBench(int Physical, uint32_t Pid, uint64_t Address,
                        uint64_t Count, uint32_t Size) {
  LARGE_INTEGER Frequency;
  LARGE_INTEGER Start;
  LARGE_INTEGER End;
  uint8_t *Buffer;
  uint64_t Checksum = 0;
  uint64_t Index;
  double Seconds;
  double TotalBytes;

  if (Count == 0 || Size == 0 || Size > RESPONSE_DATA_SIZE) {
    printf("bad bench arguments\n");
    return 0;
  }
  Buffer = (uint8_t *)malloc(Size);
  if (Buffer == NULL) {
    return 0;
  }
  ZeroMemory(Buffer, Size);
  if (!QueryPerformanceFrequency(&Frequency)) {
    free(Buffer);
    return 0;
  }

  printf("%s address=0x%llx count=%llu size=%u\n",
         Physical ? "benchphys" : "benchread", (unsigned long long)Address,
         (unsigned long long)Count, Size);
  QueryPerformanceCounter(&Start);
  for (Index = 0; Index < Count; Index++) {
    int Ok = Physical ? ReadPhys(Address, Buffer, Size)
                      : ReadVirt(Pid, Address, Buffer, Size);
    if (!Ok) {
      printf("read failed at iteration=%llu\n", (unsigned long long)Index);
      free(Buffer);
      return 0;
    }
    Checksum += Buffer[0];
    Checksum += ((uint64_t)Buffer[Size - 1]) << 8;
  }
  QueryPerformanceCounter(&End);

  Seconds = (double)(End.QuadPart - Start.QuadPart) /
            (double)Frequency.QuadPart;
  TotalBytes = (double)Count * (double)Size;
  printf("seconds=%.6f ops_per_sec=%.2f mib_per_sec=%.2f checksum=0x%llx\n",
         Seconds, (double)Count / Seconds,
         (TotalBytes / (1024.0 * 1024.0)) / Seconds,
         (unsigned long long)Checksum);
  free(Buffer);
  return 1;
}

static int RunRingBench(uint32_t TargetPid, uint64_t TargetVa, uint64_t Count,
                        uint32_t Size, uint32_t RingKb) {
  LARGE_INTEGER Frequency;
  LARGE_INTEGER Start;
  LARGE_INTEGER End;
  RING_HEADER *Ring;
  SIZE_T RingSize = (SIZE_T)RingKb * 1024U;
  double Seconds;
  double TotalBytes;
  int Locked;
  uint32_t FinalStatus;

  if (RingSize < 4096 || Count == 0 || Size == 0 ||
      Size > RESPONSE_DATA_SIZE) {
    printf("bad ringbench arguments\n");
    return 0;
  }
  Ring = (RING_HEADER *)VirtualAlloc(NULL, RingSize, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
  if (Ring == NULL) {
    printf("VirtualAlloc failed error=0x%08lX\n", GetLastError());
    return 0;
  }
  ZeroMemory(Ring, RingSize);
  for (SIZE_T Offset = 0; Offset < RingSize; Offset += 4096) {
    ((volatile uint8_t *)Ring)[Offset] = 0;
  }
  Locked = VirtualLock(Ring, RingSize);
  if (!Locked) {
    printf("VirtualLock warning error=0x%08lX\n", GetLastError());
  }

  Ring->Magic = RING_MAGIC;
  Ring->Version = RING_VERSION;
  Ring->HeaderSize = sizeof(*Ring);
  Ring->Op = RING_OP_BENCH_READ;
  Ring->Status = 0xFFFFFFFFU;
  Ring->Sequence = GetTickCount64();
  Ring->TargetPid = TargetPid;
  Ring->Size = Size;
  Ring->TargetVa = TargetVa;
  Ring->Count = Count;

  printf("ringbench pid=%u va=0x%llx count=%llu size=%u ring=%uKB\n",
         TargetPid, (unsigned long long)TargetVa, (unsigned long long)Count,
         Size, RingKb);

  if (!AttachRing(GetCurrentProcessId(), (uint64_t)(uintptr_t)Ring,
                  (uint64_t)RingSize)) {
    printf("AttachRing failed\n");
    if (Locked) {
      VirtualUnlock(Ring, RingSize);
    }
    VirtualFree(Ring, 0, MEM_RELEASE);
    return 0;
  }
  if (!QueryPerformanceFrequency(&Frequency)) {
    if (Locked) {
      VirtualUnlock(Ring, RingSize);
    }
    VirtualFree(Ring, 0, MEM_RELEASE);
    return 0;
  }
  QueryPerformanceCounter(&Start);
  if (!RunRing()) {
    printf("RunRing failed\n");
    if (Locked) {
      VirtualUnlock(Ring, RingSize);
    }
    VirtualFree(Ring, 0, MEM_RELEASE);
    return 0;
  }
  QueryPerformanceCounter(&End);

  Seconds = (double)(End.QuadPart - Start.QuadPart) /
            (double)Frequency.QuadPart;
  TotalBytes = (double)Ring->Completed * (double)Size;
  printf("status=0x%08x completed=%llu seconds=%.6f ops_per_sec=%.2f mib_per_sec=%.2f checksum=0x%llx cycles_per_op=%.2f\n",
         Ring->Status, (unsigned long long)Ring->Completed, Seconds,
         (double)Ring->Completed / Seconds,
         (TotalBytes / (1024.0 * 1024.0)) / Seconds,
         (unsigned long long)Ring->Checksum,
         Ring->Completed != 0
             ? (double)(Ring->TscEnd - Ring->TscStart) /
                   (double)Ring->Completed
             : 0.0);

  FinalStatus = Ring->Status;
  if (Locked) {
    VirtualUnlock(Ring, RingSize);
  }
  VirtualFree(Ring, 0, MEM_RELEASE);
  return FinalStatus == STATUS_OK;
}

int wmain(int argc, wchar_t **argv) {
  int Arg = 1;
  const wchar_t *Command;
  int Ok = 0;

  if (argc > 1 && _wcsicmp(argv[1], L"-v") == 0) {
    gVerbose = 1;
    Arg++;
  }
  Command = (Arg < argc) ? argv[Arg] : L"ping";

  if (_wcsicmp(Command, L"help") == 0 || _wcsicmp(Command, L"-h") == 0 ||
      _wcsicmp(Command, L"--help") == 0 || _wcsicmp(Command, L"/?") == 0) {
    Usage();
    return 0;
  }

  if (_wcsicmp(Command, L"ping") == 0) {
    Ok = OpenApi() && Ping();
    printf("%s\n", Ok ? "pong" : "failed");
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"diag") == 0) {
    DIAG_INFO Info;
    ZeroMemory(&Info, sizeof(Info));
    Ok = OpenApi() && Diag(&Info);
    if (Ok) {
      PrintDiag(&Info);
    } else {
      printf("Diag failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"findpid") == 0 && Arg + 1 < argc) {
    PROCESS_INFO Process;
    uint64_t Pid;
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL) {
      printf("bad pid\n");
      return 1;
    }
    Ok = OpenApi() && FindProcessByPid((uint32_t)Pid, &Process);
    if (Ok) {
      PrintProcess(&Process);
    } else {
      printf("FindProcessByPid failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"findproc") == 0 && Arg + 1 < argc) {
    PROCESS_INFO Process;
    char Name[NAME_SIZE];
    if (!WideToAscii(argv[Arg + 1], Name, sizeof(Name))) {
      printf("bad name\n");
      return 1;
    }
    Ok = OpenApi() && FindProcessByName(Name, &Process);
    if (Ok) {
      PrintProcess(&Process);
    } else {
      printf("FindProcessByName failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if ((_wcsicmp(Command, L"kernel") == 0 ||
       _wcsicmp(Command, L"kmodule") == 0) &&
      Arg + 1 < argc) {
    MODULE_INFO Module;
    char Name[NAME_SIZE];
    if (!WideToAscii(argv[Arg + 1], Name, sizeof(Name))) {
      printf("bad name\n");
      return 1;
    }
    Ok = OpenApi() && FindKernelModule(Name, &Module);
    if (Ok) {
      PrintModule(&Module);
    } else {
      printf("FindKernelModule failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"module") == 0 && Arg + 2 < argc) {
    PROCESS_INFO Process;
    MODULE_INFO Module;
    uint64_t Pid;
    char Name[NAME_SIZE];
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !WideToAscii(argv[Arg + 2], Name, sizeof(Name))) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && FindProcessByPid((uint32_t)Pid, &Process) &&
         FindModule(&Process, Name, &Module);
    if (Ok) {
      PrintModule(&Module);
    } else {
      printf("FindModule failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"translate") == 0 && Arg + 2 < argc) {
    uint64_t Pid;
    uint64_t Va;
    uint64_t Pa = 0;
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !ParseU64(argv[Arg + 2], &Va)) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && TranslateVirt((uint32_t)Pid, Va, &Pa);
    if (Ok) {
      printf("pa=0x%llx\n", (unsigned long long)Pa);
    } else {
      printf("TranslateVirt failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"readphys") == 0 && Arg + 2 < argc) {
    uint64_t Address;
    uint64_t Size64;
    uint8_t *Buffer;
    if (!ParseU64(argv[Arg + 1], &Address) ||
        !ParseU64(argv[Arg + 2], &Size64) || Size64 == 0 ||
        Size64 > 16 * 1024 * 1024) {
      printf("bad arguments\n");
      return 1;
    }
    Buffer = (uint8_t *)malloc((size_t)Size64);
    if (Buffer == NULL) {
      return 1;
    }
    Ok = OpenApi() && ReadPhys(Address, Buffer, (uint32_t)Size64);
    if (Ok && Arg + 3 < argc) {
      Ok = WriteFileAll(argv[Arg + 3], Buffer, (uint32_t)Size64);
    } else if (Ok) {
      HexDump(Address, Buffer, (uint32_t)Size64);
    } else {
      printf("ReadPhys failed\n");
    }
    free(Buffer);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"readvirt") == 0 && Arg + 3 < argc) {
    uint64_t Pid;
    uint64_t Address;
    uint64_t Size64;
    uint8_t *Buffer;
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !ParseU64(argv[Arg + 2], &Address) ||
        !ParseU64(argv[Arg + 3], &Size64) || Size64 == 0 ||
        Size64 > 16 * 1024 * 1024) {
      printf("bad arguments\n");
      return 1;
    }
    Buffer = (uint8_t *)malloc((size_t)Size64);
    if (Buffer == NULL) {
      return 1;
    }
    Ok = OpenApi() &&
         ReadVirt((uint32_t)Pid, Address, Buffer, (uint32_t)Size64);
    if (Ok && Arg + 4 < argc) {
      Ok = WriteFileAll(argv[Arg + 4], Buffer, (uint32_t)Size64);
    } else if (Ok) {
      HexDump(Address, Buffer, (uint32_t)Size64);
    } else {
      printf("ReadVirt failed\n");
    }
    free(Buffer);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"benchphys") == 0 && Arg + 1 < argc) {
    uint64_t Address;
    uint64_t Count = 1000000ULL;
    uint64_t Size64 = 8;
    if (!ParseU64(argv[Arg + 1], &Address) ||
        (Arg + 2 < argc && !ParseU64(argv[Arg + 2], &Count)) ||
        (Arg + 3 < argc && !ParseU64(argv[Arg + 3], &Size64)) ||
        Size64 == 0 || Size64 > RESPONSE_DATA_SIZE) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && RunReadBench(1, 0, Address, Count, (uint32_t)Size64);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"benchread") == 0 && Arg + 2 < argc) {
    uint64_t Pid;
    uint64_t Address;
    uint64_t Count = 1000000ULL;
    uint64_t Size64 = 8;
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !ParseU64(argv[Arg + 2], &Address) ||
        (Arg + 3 < argc && !ParseU64(argv[Arg + 3], &Count)) ||
        (Arg + 4 < argc && !ParseU64(argv[Arg + 4], &Size64)) ||
        Size64 == 0 || Size64 > RESPONSE_DATA_SIZE) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() &&
         RunReadBench(0, (uint32_t)Pid, Address, Count, (uint32_t)Size64);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"ringbench") == 0 && Arg + 2 < argc) {
    uint64_t Pid;
    uint64_t Address;
    uint64_t Count = 1000000ULL;
    uint64_t Size64 = 8;
    uint64_t RingKb = 64;
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !ParseU64(argv[Arg + 2], &Address) ||
        (Arg + 3 < argc && !ParseU64(argv[Arg + 3], &Count)) ||
        (Arg + 4 < argc && !ParseU64(argv[Arg + 4], &Size64)) ||
        (Arg + 5 < argc && !ParseU64(argv[Arg + 5], &RingKb)) ||
        Size64 == 0 || Size64 > RESPONSE_DATA_SIZE || RingKb < 4 ||
        RingKb > 65536) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && RunRingBench((uint32_t)Pid, Address, Count,
                                   (uint32_t)Size64, (uint32_t)RingKb);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"writephys") == 0 && Arg + 2 < argc) {
    uint64_t Address;
    uint8_t *Buffer = NULL;
    uint32_t Size = 0;
    if (!ParseU64(argv[Arg + 1], &Address) ||
        !ParseBytesArg(argv[Arg + 2], &Buffer, &Size)) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && WritePhys(Address, Buffer, Size);
    printf("%s size=0x%x\n", Ok ? "WritePhys ok" : "WritePhys failed", Size);
    free(Buffer);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"writevirt") == 0 && Arg + 3 < argc) {
    uint64_t Pid;
    uint64_t Address;
    uint8_t *Buffer = NULL;
    uint32_t Size = 0;
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !ParseU64(argv[Arg + 2], &Address) ||
        !ParseBytesArg(argv[Arg + 3], &Buffer, &Size)) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && WriteVirt((uint32_t)Pid, Address, Buffer, Size);
    printf("%s size=0x%x\n", Ok ? "WriteVirt ok" : "WriteVirt failed", Size);
    free(Buffer);
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"kexport") == 0 && Arg + 2 < argc) {
    MODULE_INFO Module;
    uint64_t Address = 0;
    char ModuleName[NAME_SIZE];
    char ExportName[NAME_SIZE];
    if (!WideToAscii(argv[Arg + 1], ModuleName, sizeof(ModuleName)) ||
        !WideToAscii(argv[Arg + 2], ExportName, sizeof(ExportName))) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && FindKernelModule(ModuleName, &Module) &&
         FindExport(&Module, ExportName, &Address);
    if (Ok) {
      PrintModule(&Module);
      printf("%s=0x%llx\n", ExportName, (unsigned long long)Address);
    } else {
      printf("kexport failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"export") == 0 && Arg + 3 < argc) {
    PROCESS_INFO Process;
    MODULE_INFO Module;
    uint64_t Pid;
    uint64_t Address = 0;
    char ModuleName[NAME_SIZE];
    char ExportName[NAME_SIZE];
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !WideToAscii(argv[Arg + 2], ModuleName, sizeof(ModuleName)) ||
        !WideToAscii(argv[Arg + 3], ExportName, sizeof(ExportName))) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && FindProcessByPid((uint32_t)Pid, &Process) &&
         FindModule(&Process, ModuleName, &Module) &&
         FindExport(&Module, ExportName, &Address);
    if (Ok) {
      PrintModule(&Module);
      printf("%s=0x%llx\n", ExportName, (unsigned long long)Address);
    } else {
      printf("export failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"dumpkernel") == 0 && Arg + 2 < argc) {
    MODULE_INFO Module;
    char ModuleName[NAME_SIZE];
    if (!WideToAscii(argv[Arg + 1], ModuleName, sizeof(ModuleName))) {
      printf("bad module name\n");
      return 1;
    }
    Ok = OpenApi() && FindKernelModule(ModuleName, &Module) &&
         DumpModuleToFile(&Module, argv[Arg + 2]);
    if (Ok) {
      PrintModule(&Module);
    } else {
      printf("dumpkernel failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  if (_wcsicmp(Command, L"dump") == 0 && Arg + 3 < argc) {
    PROCESS_INFO Process;
    MODULE_INFO Module;
    uint64_t Pid;
    char ModuleName[NAME_SIZE];
    if (!ParseU64(argv[Arg + 1], &Pid) || Pid > 0xFFFFFFFFULL ||
        !WideToAscii(argv[Arg + 2], ModuleName, sizeof(ModuleName))) {
      printf("bad arguments\n");
      return 1;
    }
    Ok = OpenApi() && FindProcessByPid((uint32_t)Pid, &Process) &&
         FindModule(&Process, ModuleName, &Module) &&
         DumpModuleToFile(&Module, argv[Arg + 3]);
    if (Ok) {
      PrintModule(&Module);
    } else {
      printf("dump failed\n");
    }
    Close();
    return Ok ? 0 : 1;
  }

  Usage();
  return 1;
}
#endif
