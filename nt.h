#pragma once
#include <windows.h>
#include <winnt.h>

#define PAGE_SIZE 0x1000
#define GetPml4eIndex(address)		((address >> 39) & 0x1ff)
#define GetPdpteIndex(address)		((address >> 30) & 0x1ff)
#define GetPdeIndex(address)		((address >> 21) & 0x1ff)
#define GetPteIndex(address)		((address >> 12) & 0x1ff)
#define ReadDricetoryTable(address, index)	((PVOID)(address + index * 8))
#define GET_OFFSET_64(structure, member) ((int64_t)&((structure*)0)->member) // 64

#define ADDRESS_CALC_ALIGNMENT(address) ((address & 0xFFF)? PAGE_SIZE-(address & 0xFFF):PAGE_SIZE)
#define ADDRESS_CALC(address,size) (size > PAGE_SIZE ? ADDRESS_CALC_ALIGNMENT(address) : size)
//0x10 bytes (sizeof)
typedef struct _KDESCRIPTOR
{
	USHORT Pad[3];                                                          //0x0
	USHORT Limit;                                                           //0x6
	VOID* Base;                                                             //0x8
}KDESCRIPTOR;

//0xf0 bytes (sizeof)
typedef struct _KSPECIAL_REGISTERS
{
	ULONGLONG Cr0;                                                          //0x0
	ULONGLONG Cr2;                                                          //0x8
	ULONGLONG Cr3;                                                          //0x10
	ULONGLONG Cr4;                                                          //0x18
	ULONGLONG KernelDr0;                                                    //0x20
	ULONGLONG KernelDr1;                                                    //0x28
	ULONGLONG KernelDr2;                                                    //0x30
	ULONGLONG KernelDr3;                                                    //0x38
	ULONGLONG KernelDr6;                                                    //0x40
	ULONGLONG KernelDr7;                                                    //0x48
	KDESCRIPTOR Gdtr;														//0x50
	KDESCRIPTOR Idtr;														//0x60
	USHORT Tr;                                                              //0x70
	USHORT Ldtr;                                                            //0x72
	ULONG MxCsr;                                                            //0x74
	ULONGLONG DebugControl;                                                 //0x78
	ULONGLONG LastBranchToRip;                                              //0x80
	ULONGLONG LastBranchFromRip;                                            //0x88
	ULONGLONG LastExceptionToRip;                                           //0x90
	ULONGLONG LastExceptionFromRip;                                         //0x98
	ULONGLONG Cr8;                                                          //0xa0
	ULONGLONG MsrGsBase;                                                    //0xa8
	ULONGLONG MsrGsSwap;                                                    //0xb0
	ULONGLONG MsrStar;                                                      //0xb8
	ULONGLONG MsrLStar;                                                     //0xc0
	ULONGLONG MsrCStar;                                                     //0xc8
	ULONGLONG MsrSyscallMask;                                               //0xd0
	ULONGLONG Xcr0;                                                         //0xd8
	ULONGLONG MsrFsBase;                                                    //0xe0
	ULONGLONG SpecialPadding0;                                              //0xe8
}KSPECIAL_REGISTERS;

//0x5c0 bytes (sizeof)
typedef struct _KPROCESSOR_STATE
{
	KSPECIAL_REGISTERS SpecialRegisters;                            //0x0
	CONTEXT ContextFrame;                                           //0xf0
}KPROCESSOR_STATE;

#define PSB_GDT32_NULL      0 * 16
#define PSB_GDT32_CODE64    1 * 16
#define PSB_GDT32_DATA32    2 * 16
#define PSB_GDT32_CODE32    3 * 16
#define PSB_GDT32_MAX       3

#pragma pack(push,2)
typedef struct _FAR_JMP_16
{
	UCHAR  OpCode;  // = 0xe9
	USHORT Offset;
} FAR_JMP_16;

typedef struct _FAR_TARGET_32
{
	ULONG Offset;
	USHORT Selector;
} FAR_TARGET_32;

typedef struct _PSEUDO_DESCRIPTOR_32
{
	USHORT Limit;
	ULONG Base;
} PSEUDO_DESCRIPTOR_32;

#pragma pack(pop)

typedef union _KGDTENTRY64
{
	struct
	{
		USHORT  LimitLow;
		USHORT  BaseLow;
		union
		{
			struct
			{
				UCHAR   BaseMiddle;
				UCHAR   Flags1;
				UCHAR   Flags2;
				UCHAR   BaseHigh;
			} Bytes;

			struct
			{
				ULONG   BaseMiddle : 8;
				ULONG   Type : 5;
				ULONG   Dpl : 2;
				ULONG   Present : 1;
				ULONG   LimitHigh : 4;
				ULONG   System : 1;
				ULONG   LongMode : 1;
				ULONG   DefaultBig : 1;
				ULONG   Granularity : 1;
				ULONG   BaseHigh : 8;
			} Bits;
		};
		ULONG BaseUpper;
		ULONG MustBeZero;
	};

	ULONG64 Alignment;
} KGDTENTRY64, * PKGDTENTRY64;

typedef struct _PROCESSOR_START_BLOCK
{
	FAR_JMP_16 Jmp;
	ULONG CompletionFlag;
	PSEUDO_DESCRIPTOR_32 Gdt32;
	PSEUDO_DESCRIPTOR_32 Idt32;
	KGDTENTRY64 Gdt[PSB_GDT32_MAX + 1];
	ULONG64 TiledCr3;
	FAR_TARGET_32 PmTarget;
	FAR_TARGET_32 LmIdentityTarget;
	PVOID LmTarget;
	_PROCESSOR_START_BLOCK* SelfMap;
	ULONG64 MsrPat;
	ULONG64 MsrEFER;
	KPROCESSOR_STATE ProcessorState;
} PROCESSOR_START_BLOCK;

//0x18 bytes (sizeof)
typedef struct _DISPATCHER_HEADER
{
	union
	{
		volatile LONG Lock;                                                 //0x0
		LONG LockNV;                                                        //0x0
		struct
		{
			UCHAR Type;                                                     //0x0
			UCHAR Signalling;                                               //0x1
			UCHAR Size;                                                     //0x2
			UCHAR Reserved1;                                                //0x3
		};
		struct
		{
			UCHAR TimerType;                                                //0x0
			union
			{
				UCHAR TimerControlFlags;                                    //0x1
				struct
				{
					UCHAR Absolute : 1;                                       //0x1
					UCHAR Wake : 1;                                           //0x1
					UCHAR EncodedTolerableDelay : 6;                          //0x1
				};
			};
			UCHAR Hand;                                                     //0x2
			union
			{
				UCHAR TimerMiscFlags;                                       //0x3
				struct
				{
					UCHAR Index : 6;                                          //0x3
					UCHAR Inserted : 1;                                       //0x3
					volatile UCHAR Expired : 1;                               //0x3
				};
			};
		};
		struct
		{
			UCHAR Timer2Type;                                               //0x0
			union
			{
				UCHAR Timer2Flags;                                          //0x1
				struct
				{
					UCHAR Timer2Inserted : 1;                                 //0x1
					UCHAR Timer2Expiring : 1;                                 //0x1
					UCHAR Timer2CancelPending : 1;                            //0x1
					UCHAR Timer2SetPending : 1;                               //0x1
					UCHAR Timer2Running : 1;                                  //0x1
					UCHAR Timer2Disabled : 1;                                 //0x1
					UCHAR Timer2ReservedFlags : 2;                            //0x1
				};
			};
			UCHAR Timer2ComponentId;                                        //0x2
			UCHAR Timer2RelativeId;                                         //0x3
		};
		struct
		{
			UCHAR QueueType;                                                //0x0
			union
			{
				UCHAR QueueControlFlags;                                    //0x1
				struct
				{
					UCHAR Abandoned : 1;                                      //0x1
					UCHAR DisableIncrement : 1;                               //0x1
					UCHAR QueueReservedControlFlags : 6;                      //0x1
				};
			};
			UCHAR QueueSize;                                                //0x2
			UCHAR QueueReserved;                                            //0x3
		};
		struct
		{
			UCHAR ThreadType;                                               //0x0
			UCHAR ThreadReserved;                                           //0x1
			union
			{
				UCHAR ThreadControlFlags;                                   //0x2
				struct
				{
					UCHAR CycleProfiling : 1;                                 //0x2
					UCHAR CounterProfiling : 1;                               //0x2
					UCHAR GroupScheduling : 1;                                //0x2
					UCHAR AffinitySet : 1;                                    //0x2
					UCHAR Tagged : 1;                                         //0x2
					UCHAR EnergyProfiling : 1;                                //0x2
					UCHAR SchedulerAssist : 1;                                //0x2
					UCHAR ThreadReservedControlFlags : 1;                     //0x2
				};
			};
			union
			{
				UCHAR DebugActive;                                          //0x3
				struct
				{
					UCHAR ActiveDR7 : 1;                                      //0x3
					UCHAR Instrumented : 1;                                   //0x3
					UCHAR Minimal : 1;                                        //0x3
					UCHAR Reserved4 : 2;                                      //0x3
					UCHAR AltSyscall : 1;                                     //0x3
					UCHAR UmsScheduled : 1;                                   //0x3
					UCHAR UmsPrimary : 1;                                     //0x3
				};
			};
		};
		struct
		{
			UCHAR MutantType;                                               //0x0
			UCHAR MutantSize;                                               //0x1
			UCHAR DpcActive;                                                //0x2
			UCHAR MutantReserved;                                           //0x3
		};
	};
	LONG SignalState;                                                       //0x4
	struct _LIST_ENTRY WaitListHead;                                        //0x8
}DISPATCHER_HEADER;

//0xa8 bytes (sizeof)
typedef struct _KAFFINITY_EX
{
	USHORT Count;                                                           //0x0
	USHORT Size;                                                            //0x2
	ULONG Reserved;                                                         //0x4
	ULONGLONG Bitmap[20];                                                   //0x8
}KAFFINITY_EX;

//0x1 bytes (sizeof)
typedef union _KEXECUTE_OPTIONS
{
	UCHAR ExecuteDisable : 1;                                                 //0x0
	UCHAR ExecuteEnable : 1;                                                  //0x0
	UCHAR DisableThunkEmulation : 1;                                          //0x0
	UCHAR Permanent : 1;                                                      //0x0
	UCHAR ExecuteDispatchEnable : 1;                                          //0x0
	UCHAR ImageDispatchEnable : 1;                                            //0x0
	UCHAR DisableExceptionChainValidation : 1;                                //0x0
	UCHAR Spare : 1;                                                          //0x0
	volatile UCHAR ExecuteOptions;                                          //0x0
	UCHAR ExecuteOptionsNV;                                                 //0x0
}KEXECUTE_OPTIONS;

//0x4 bytes (sizeof)
typedef union _KSTACK_COUNT
{
	LONG Value;                                                             //0x0
	ULONG State : 3;                                                          //0x0
	ULONG StackCount : 29;                                                    //0x0
}KSTACK_COUNT;

//0x8 bytes (sizeof)
typedef struct _KSCHEDULING_GROUP_POLICY
{
	union
	{
		ULONG Value;                                                        //0x0
		USHORT Weight;                                                      //0x0
		struct
		{
			USHORT MinRate;                                                 //0x0
			USHORT MaxRate;                                                 //0x2
		};
	};
	union
	{
		ULONG AllFlags;                                                     //0x4
		struct
		{
			ULONG Type : 1;                                                   //0x4
			ULONG Disabled : 1;                                               //0x4
			ULONG RankBias : 1;                                               //0x4
			ULONG Spare1 : 29;                                                //0x4
		};
	};
}KSCHEDULING_GROUP_POLICY;

//0x40 bytes (sizeof)
typedef struct _KDPC
{
	union
	{
		ULONG TargetInfoAsUlong;                                            //0x0
		struct
		{
			UCHAR Type;                                                     //0x0
			UCHAR Importance;                                               //0x1
			volatile USHORT Number;                                         //0x2
		};
	};
	SINGLE_LIST_ENTRY DpcListEntry;                                 //0x8
	ULONGLONG ProcessorHistory;                                             //0x10
	VOID(*DeferredRoutine)(struct _KDPC* arg1, VOID* arg2, VOID* arg3, VOID* arg4); //0x18
	VOID* DeferredContext;                                                  //0x20
	VOID* SystemArgument1;                                                  //0x28
	VOID* SystemArgument2;                                                  //0x30
	VOID* DpcData;                                                          //0x38
}KDPC;

//0x18 bytes (sizeof)
typedef struct _RTL_BALANCED_NODE
{
	union
	{
		PVOID Children[2];                             //0x0
		struct
		{
			PVOID Left;                                //0x0
			PVOID Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
}RTL_BALANCED_NODE;

//0x10 bytes (sizeof)
typedef struct _RTL_RB_TREE
{
	RTL_BALANCED_NODE* Root;                                        //0x0
	union
	{
		UCHAR Encoded : 1;                                                    //0x8
		RTL_BALANCED_NODE* Min;                                     //0x8
	};
}RTL_RB_TREE;

//0x1a8 bytes (sizeof)
typedef struct _KSCB
{
	ULONGLONG GenerationCycles;                                             //0x0
	ULONGLONG MinQuotaCycleTarget;                                          //0x8
	ULONGLONG MaxQuotaCycleTarget;                                          //0x10
	ULONGLONG RankCycleTarget;                                              //0x18
	ULONGLONG LongTermCycles;                                               //0x20
	ULONGLONG LastReportedCycles;                                           //0x28
	volatile ULONGLONG OverQuotaHistory;                                    //0x30
	ULONGLONG ReadyTime;                                                    //0x38
	ULONGLONG InsertTime;                                                   //0x40
	LIST_ENTRY PerProcessorList;                                    //0x48
	RTL_BALANCED_NODE QueueNode;                                    //0x58
	UCHAR Inserted : 1;                                                       //0x70
	UCHAR MaxOverQuota : 1;                                                   //0x70
	UCHAR MinOverQuota : 1;                                                   //0x70
	UCHAR RankBias : 1;                                                       //0x70
	UCHAR SoftCap : 1;                                                        //0x70
	UCHAR ShareRankOwner : 1;                                                 //0x70
	UCHAR Spare1 : 2;                                                         //0x70
	UCHAR Depth;                                                            //0x71
	USHORT ReadySummary;                                                    //0x72
	ULONG Rank;                                                             //0x74
	volatile ULONG* ShareRank;                                              //0x78
	volatile ULONG OwnerShareRank;                                          //0x80
	LIST_ENTRY ReadyListHead[16];                                   //0x88
	RTL_RB_TREE ChildScbQueue;                                      //0x188
	PVOID Parent;                                                   //0x198
	PVOID Root;                                                     //0x1a0
}KSCB;

//0x240 bytes (sizeof)
typedef struct _KSCHEDULING_GROUP
{
	KSCHEDULING_GROUP_POLICY Policy;                                //0x0
	ULONG RelativeWeight;                                                   //0x8
	ULONG ChildMinRate;                                                     //0xc
	ULONG ChildMinWeight;                                                   //0x10
	ULONG ChildTotalWeight;                                                 //0x14
	ULONGLONG QueryHistoryTimeStamp;                                        //0x18
	LONGLONG NotificationCycles;                                            //0x20
	LONGLONG MaxQuotaLimitCycles;                                           //0x28
	volatile LONGLONG MaxQuotaCyclesRemaining;                              //0x30
	union
	{
		LIST_ENTRY SchedulingGroupList;                             //0x38
		LIST_ENTRY Sibling;                                         //0x38
	};
	KDPC* NotificationDpc;                                          //0x48
	LIST_ENTRY ChildList;                                           //0x50
	PVOID Parent;                                      //0x60
	KSCB PerProcessor[1];                                           //0x80
}KSCHEDULING_GROUP;

//0x438 bytes (sizeof)
typedef struct _KPROCESS
{
	DISPATCHER_HEADER Header;							                    //0x0
	LIST_ENTRY ProfileListHead;											    //0x18
	ULONGLONG DirectoryTableBase;                                           //0x28
	LIST_ENTRY ThreadListHead;									            //0x30
	ULONG ProcessLock;                                                      //0x40
	ULONG ProcessTimerDelay;                                                //0x44
	ULONGLONG DeepFreezeStartTime;                                          //0x48
	KAFFINITY_EX Affinity;													//0x50
	ULONGLONG AffinityPadding[12];                                          //0xf8
	LIST_ENTRY ReadyListHead;												//0x158
	SINGLE_LIST_ENTRY SwapListEntry;										//0x168
	volatile  KAFFINITY_EX ActiveProcessors;								//0x170
	ULONGLONG ActiveProcessorsPadding[12];                                  //0x218
	union
	{
		struct
		{
			ULONG AutoAlignment : 1;                                          //0x278
			ULONG DisableBoost : 1;                                           //0x278
			ULONG DisableQuantum : 1;                                         //0x278
			ULONG DeepFreeze : 1;                                             //0x278
			ULONG TimerVirtualization : 1;                                    //0x278
			ULONG CheckStackExtents : 1;                                      //0x278
			ULONG CacheIsolationEnabled : 1;                                  //0x278
			ULONG PpmPolicy : 3;                                              //0x278
			ULONG VaSpaceDeleted : 1;                                         //0x278
			ULONG ReservedFlags : 21;                                         //0x278
		};
		volatile LONG ProcessFlags;                                         //0x278
	};
	ULONG ActiveGroupsMask;                                                 //0x27c
	CHAR BasePriority;                                                      //0x280
	CHAR QuantumReset;                                                      //0x281
	CHAR Visited;                                                           //0x282
	KEXECUTE_OPTIONS Flags;                                          //0x283
	USHORT ThreadSeed[20];                                                  //0x284
	USHORT ThreadSeedPadding[12];                                           //0x2ac
	USHORT IdealProcessor[20];                                              //0x2c4
	USHORT IdealProcessorPadding[12];                                       //0x2ec
	USHORT IdealNode[20];                                                   //0x304
	USHORT IdealNodePadding[12];                                            //0x32c
	USHORT IdealGlobalNode;                                                 //0x344
	USHORT Spare1;                                                          //0x346
	KSTACK_COUNT StackCount;                                 //0x348
	LIST_ENTRY ProcessListEntry;                                    //0x350
	ULONGLONG CycleTime;                                                    //0x360
	ULONGLONG ContextSwitches;                                              //0x368
	KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
	ULONG FreezeCount;                                                      //0x378
	ULONG KernelTime;                                                       //0x37c
	ULONG UserTime;                                                         //0x380
	ULONG ReadyTime;                                                        //0x384
	ULONGLONG UserDirectoryTableBase;                                       //0x388
	UCHAR AddressPolicy;                                                    //0x390
	UCHAR Spare2[71];                                                       //0x391
	VOID* InstrumentationCallback;                                          //0x3d8
	union
	{
		ULONGLONG SecureHandle;                                             //0x3e0
		struct
		{
			ULONGLONG SecureProcess : 1;                                      //0x3e0
			ULONGLONG Unused : 1;                                             //0x3e0
		} Flags;                                                            //0x3e0
	} SecureState;                                                          //0x3e0
	ULONGLONG KernelWaitTime;                                               //0x3e8
	ULONGLONG UserWaitTime;                                                 //0x3f0
	ULONGLONG EndPadding[8];                                                //0x3f8
}KPROCESS, * PKPROCESS;

//0x8 bytes (sizeof)
typedef struct EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
}EX_PUSH_LOCK;

//0x8 bytes (sizeof)
typedef struct _EX_RUNDOWN_REF
{
	union
	{
		ULONGLONG Count;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
}EX_RUNDOWN_REF;

//0x8 bytes (sizeof)
typedef struct _EX_FAST_REF
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONGLONG RefCnt : 4;                                                 //0x0
		ULONGLONG Value;                                                    //0x0
	};
}EX_FAST_REF;

//0x8 bytes (sizeof)
typedef struct _RTL_AVL_TREE
{
	RTL_BALANCED_NODE* Root;                                        //0x0
}RTL_AVL_TREE;

//0x8 bytes (sizeof)
typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	PVOID ImageFileName;                         //0x0
}SE_AUDIT_PROCESS_CREATION_INFO;

//0x4 bytes (sizeof)
typedef struct _MMSUPPORT_FLAGS
{
	union
	{
		struct
		{
			UCHAR WorkingSetType : 3;                                         //0x0
			UCHAR Reserved0 : 3;                                              //0x0
			UCHAR MaximumWorkingSetHard : 1;                                  //0x0
			UCHAR MinimumWorkingSetHard : 1;                                  //0x0
			UCHAR SessionMaster : 1;                                          //0x1
			UCHAR TrimmerState : 2;                                           //0x1
			UCHAR Reserved : 1;                                               //0x1
			UCHAR PageStealers : 4;                                           //0x1
		};
		USHORT u1;                                                          //0x0
	};
	UCHAR MemoryPriority;                                                   //0x2
	union
	{
		struct
		{
			UCHAR WsleDeleted : 1;                                            //0x3
			UCHAR SvmEnabled : 1;                                             //0x3
			UCHAR ForceAge : 1;                                               //0x3
			UCHAR ForceTrim : 1;                                              //0x3
			UCHAR NewMaximum : 1;                                             //0x3
			UCHAR CommitReleaseState : 2;                                     //0x3
		};
		UCHAR u2;                                                           //0x3
	};
}MMSUPPORT_FLAGS;

//0x20 bytes (sizeof)
typedef struct _ALPC_PROCESS_CONTEXT
{
	EX_PUSH_LOCK Lock;                                              //0x0
	LIST_ENTRY ViewListHead;                                        //0x8
	volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
}ALPC_PROCESS_CONTEXT;

//0xc0 bytes (sizeof)
typedef struct _MMSUPPORT_INSTANCE
{
	ULONG NextPageColor;                                                    //0x0
	ULONG PageFaultCount;                                                   //0x4
	ULONGLONG TrimmedPageCount;                                             //0x8
	PVOID VmWorkingSetList;                               //0x10
	LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
	ULONGLONG AgeDistribution[8];                                           //0x28
	PVOID ExitOutswapGate;                                         //0x68
	ULONGLONG MinimumWorkingSetSize;                                        //0x70
	ULONGLONG WorkingSetLeafSize;                                           //0x78
	ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
	ULONGLONG WorkingSetSize;                                               //0x88
	ULONGLONG WorkingSetPrivateSize;                                        //0x90
	ULONGLONG MaximumWorkingSetSize;                                        //0x98
	ULONGLONG PeakWorkingSetSize;                                           //0xa0
	ULONG HardFaultCount;                                                   //0xa8
	USHORT LastTrimStamp;                                                   //0xac
	USHORT PartitionId;                                                     //0xae
	ULONGLONG SelfmapLock;                                                  //0xb0
	MMSUPPORT_FLAGS Flags;                                          //0xb8
}MMSUPPORT_INSTANCE;

//0x80 bytes (sizeof)
typedef struct _MMSUPPORT_SHARED
{
	volatile LONG WorkingSetLock;                                           //0x0
	LONG GoodCitizenWaiting;                                                //0x4
	ULONGLONG ReleasedCommitDebt;                                           //0x8
	ULONGLONG ResetPagesRepurposedCount;                                    //0x10
	VOID* WsSwapSupport;                                                    //0x18
	VOID* CommitReleaseContext;                                             //0x20
	VOID* AccessLog;                                                        //0x28
	volatile ULONGLONG ChargedWslePages;                                    //0x30
	ULONGLONG ActualWslePages;                                              //0x38
	ULONGLONG WorkingSetCoreLock;                                           //0x40
	VOID* ShadowMapping;                                                    //0x48
}MMSUPPORT_SHARED;

//0x140 bytes (sizeof)
typedef struct _MMSUPPORT_FULL
{
	MMSUPPORT_INSTANCE Instance;                                    //0x0
	MMSUPPORT_SHARED Shared;                                        //0xc0
}MMSUPPORT_FULL;

//0x1 bytes (sizeof)
typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;                                                        //0x0
		struct
		{
			UCHAR Type : 3;                                                   //0x0
			UCHAR Audit : 1;                                                  //0x0
			UCHAR Signer : 4;                                                 //0x0
		};
	};
}PS_PROTECTION;

//0x8 bytes (sizeof)
typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
	ULONGLONG DelayMs : 30;                                                   //0x0
	ULONGLONG CoalescingWindowMs : 30;                                        //0x0
	ULONGLONG Reserved : 1;                                                   //0x0
	ULONGLONG NewTimerWheel : 1;                                              //0x0
	ULONGLONG Retry : 1;                                                      //0x0
	ULONGLONG Locked : 1;                                                     //0x0
	ULONGLONG All;                                                          //0x0
}PS_INTERLOCKED_TIMER_DELAY_VALUES;

//0x8 bytes (sizeof)
typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];                                                          //0x0
}WNF_STATE_NAME;

//0x8 bytes (sizeof)
typedef struct _JOBOBJECT_WAKE_FILTER
{
	ULONG HighEdgeFilter;                                                   //0x0
	ULONG LowEdgeFilter;                                                    //0x4
}JOBOBJECT_WAKE_FILTER;

//0x30 bytes (sizeof)
typedef struct _PS_PROCESS_WAKE_INFORMATION
{
	ULONGLONG NotificationChannel;                                          //0x0
	ULONG WakeCounters[7];                                                  //0x8
	JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
	ULONG NoWakeCounter;                                                    //0x2c
}PS_PROCESS_WAKE_INFORMATION;

//0xa40 bytes (sizeof)
typedef struct _EPROCESS
{
	KPROCESS Pcb;                                                   //0x0
	EX_PUSH_LOCK ProcessLock;                                       //0x438
	VOID* UniqueProcessId;                                                  //0x440
	LIST_ENTRY ActiveProcessLinks;                                  //0x448
	EX_RUNDOWN_REF RundownProtect;                                  //0x458
	union
	{
		ULONG Flags2;                                                       //0x460
		struct
		{
			ULONG JobNotReallyActive : 1;                                     //0x460
			ULONG AccountingFolded : 1;                                       //0x460
			ULONG NewProcessReported : 1;                                     //0x460
			ULONG ExitProcessReported : 1;                                    //0x460
			ULONG ReportCommitChanges : 1;                                    //0x460
			ULONG LastReportMemory : 1;                                       //0x460
			ULONG ForceWakeCharge : 1;                                        //0x460
			ULONG CrossSessionCreate : 1;                                     //0x460
			ULONG NeedsHandleRundown : 1;                                     //0x460
			ULONG RefTraceEnabled : 1;                                        //0x460
			ULONG PicoCreated : 1;                                            //0x460
			ULONG EmptyJobEvaluated : 1;                                      //0x460
			ULONG DefaultPagePriority : 3;                                    //0x460
			ULONG PrimaryTokenFrozen : 1;                                     //0x460
			ULONG ProcessVerifierTarget : 1;                                  //0x460
			ULONG RestrictSetThreadContext : 1;                               //0x460
			ULONG AffinityPermanent : 1;                                      //0x460
			ULONG AffinityUpdateEnable : 1;                                   //0x460
			ULONG PropagateNode : 1;                                          //0x460
			ULONG ExplicitAffinity : 1;                                       //0x460
			ULONG ProcessExecutionState : 2;                                  //0x460
			ULONG EnableReadVmLogging : 1;                                    //0x460
			ULONG EnableWriteVmLogging : 1;                                   //0x460
			ULONG FatalAccessTerminationRequested : 1;                        //0x460
			ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
			ULONG ProcessStateChangeRequest : 2;                              //0x460
			ULONG ProcessStateChangeInProgress : 1;                           //0x460
			ULONG InPrivate : 1;                                              //0x460
		};
	};
	union
	{
		ULONG Flags;                                                        //0x464
		struct
		{
			ULONG CreateReported : 1;                                         //0x464
			ULONG NoDebugInherit : 1;                                         //0x464
			ULONG ProcessExiting : 1;                                         //0x464
			ULONG ProcessDelete : 1;                                          //0x464
			ULONG ManageExecutableMemoryWrites : 1;                           //0x464
			ULONG VmDeleted : 1;                                              //0x464
			ULONG OutswapEnabled : 1;                                         //0x464
			ULONG Outswapped : 1;                                             //0x464
			ULONG FailFastOnCommitFail : 1;                                   //0x464
			ULONG Wow64VaSpace4Gb : 1;                                        //0x464
			ULONG AddressSpaceInitialized : 2;                                //0x464
			ULONG SetTimerResolution : 1;                                     //0x464
			ULONG BreakOnTermination : 1;                                     //0x464
			ULONG DeprioritizeViews : 1;                                      //0x464
			ULONG WriteWatch : 1;                                             //0x464
			ULONG ProcessInSession : 1;                                       //0x464
			ULONG OverrideAddressSpace : 1;                                   //0x464
			ULONG HasAddressSpace : 1;                                        //0x464
			ULONG LaunchPrefetched : 1;                                       //0x464
			ULONG Background : 1;                                             //0x464
			ULONG VmTopDown : 1;                                              //0x464
			ULONG ImageNotifyDone : 1;                                        //0x464
			ULONG PdeUpdateNeeded : 1;                                        //0x464
			ULONG VdmAllowed : 1;                                             //0x464
			ULONG ProcessRundown : 1;                                         //0x464
			ULONG ProcessInserted : 1;                                        //0x464
			ULONG DefaultIoPriority : 3;                                      //0x464
			ULONG ProcessSelfDelete : 1;                                      //0x464
			ULONG SetTimerResolutionLink : 1;                                 //0x464
		};
	};
	union _LARGE_INTEGER CreateTime;                                        //0x468
	ULONGLONG ProcessQuotaUsage[2];                                         //0x470
	ULONGLONG ProcessQuotaPeak[2];                                          //0x480
	ULONGLONG PeakVirtualSize;                                              //0x490
	ULONGLONG VirtualSize;                                                  //0x498
	LIST_ENTRY SessionProcessLinks;                                 //0x4a0
	union
	{
		VOID* ExceptionPortData;                                            //0x4b0
		ULONGLONG ExceptionPortValue;                                       //0x4b0
		ULONGLONG ExceptionPortState : 3;                                     //0x4b0
	};
	EX_FAST_REF Token;                                              //0x4b8
	ULONGLONG MmReserved;                                                   //0x4c0
	EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
	EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
	PVOID RotateInProgress;                                      //0x4d8
	PVOID ForkInProgress;                                        //0x4e0
	PVOID volatile CommitChargeJob;                                 //0x4e8
	RTL_AVL_TREE CloneRoot;                                         //0x4f0
	volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
	volatile ULONGLONG NumberOfLockedPages;                                 //0x500
	VOID* Win32Process;                                                     //0x508
	PVOID volatile Job;                                             //0x510
	VOID* SectionObject;                                                    //0x518
	VOID* SectionBaseAddress;                                               //0x520
	ULONG Cookie;                                                           //0x528
	PVOID WorkingSetWatch;                             //0x530
	VOID* Win32WindowStation;                                               //0x538
	VOID* InheritedFromUniqueProcessId;                                     //0x540
	volatile ULONGLONG OwnerProcessId;                                      //0x548
	PVOID Peb;                                                       //0x550
	PVOID Session;                                      //0x558
	VOID* Spare1;                                                           //0x560
	PVOID QuotaBlock;                               //0x568
	PVOID ObjectTable;                                      //0x570
	VOID* DebugPort;                                                        //0x578
	PVOID WoW64Process;                                    //0x580
	VOID* DeviceMap;                                                        //0x588
	VOID* EtwDataSource;                                                    //0x590
	ULONGLONG PageDirectoryPte;                                             //0x598
	PVOID ImageFilePointer;                                  //0x5a0
	UCHAR ImageFileName[15];                                                //0x5a8
	UCHAR PriorityClass;                                                    //0x5b7
	VOID* SecurityPort;                                                     //0x5b8
	SE_AUDIT_PROCESS_CREATION_INFO  SeAuditProcessCreationInfo;      //0x5c0
	LIST_ENTRY JobLinks;                                            //0x5c8
	VOID* HighestUserAddress;                                               //0x5d8
	LIST_ENTRY ThreadListHead;                                      //0x5e0
	volatile ULONG ActiveThreads;                                           //0x5f0
	ULONG ImagePathHash;                                                    //0x5f4
	ULONG DefaultHardErrorProcessing;                                       //0x5f8
	LONG LastThreadExitStatus;                                              //0x5fc
	struct _EX_FAST_REF PrefetchTrace;                                      //0x600
	VOID* LockedPagesList;                                                  //0x608
	LARGE_INTEGER ReadOperationCount;                                //0x610
	LARGE_INTEGER WriteOperationCount;                               //0x618
	LARGE_INTEGER OtherOperationCount;                               //0x620
	LARGE_INTEGER ReadTransferCount;                                 //0x628
	LARGE_INTEGER WriteTransferCount;                                //0x630
	LARGE_INTEGER OtherTransferCount;                                //0x638
	ULONGLONG CommitChargeLimit;                                            //0x640
	volatile ULONGLONG CommitCharge;                                        //0x648
	volatile ULONGLONG CommitChargePeak;                                    //0x650
	MMSUPPORT_FULL Vm;                                              //0x680
	LIST_ENTRY MmProcessLinks;                                      //0x7c0
	ULONG ModifiedPageCount;                                                //0x7d0
	LONG ExitStatus;                                                        //0x7d4
	RTL_AVL_TREE VadRoot;                                           //0x7d8
	VOID* VadHint;                                                          //0x7e0
	ULONGLONG VadCount;                                                     //0x7e8
	volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
	ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
	ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
	LIST_ENTRY TimerResolutionLink;                                 //0x820
	PVOID TimerResolutionStackRecord;               //0x830
	ULONG RequestedTimerResolution;                                         //0x838
	ULONG SmallestTimerResolution;                                          //0x83c
	LARGE_INTEGER ExitTime;                                          //0x840
	PVOID InvertedFunctionTable;                 //0x848
	EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
	ULONG ActiveThreadsHighWatermark;                                       //0x858
	ULONG LargePrivateVadCount;                                             //0x85c
	EX_PUSH_LOCK ThreadListLock;                                    //0x860
	VOID* WnfContext;                                                       //0x868
	PVOID ServerSilo;                                               //0x870
	UCHAR SignatureLevel;                                                   //0x878
	UCHAR SectionSignatureLevel;                                            //0x879
	struct _PS_PROTECTION Protection;                                       //0x87a
	UCHAR HangCount : 3;                                                      //0x87b
	UCHAR GhostCount : 3;                                                     //0x87b
	UCHAR PrefilterException : 1;                                             //0x87b
	union
	{
		ULONG Flags3;                                                       //0x87c
		struct
		{
			ULONG Minimal : 1;                                                //0x87c
			ULONG ReplacingPageRoot : 1;                                      //0x87c
			ULONG Crashed : 1;                                                //0x87c
			ULONG JobVadsAreTracked : 1;                                      //0x87c
			ULONG VadTrackingDisabled : 1;                                    //0x87c
			ULONG AuxiliaryProcess : 1;                                       //0x87c
			ULONG SubsystemProcess : 1;                                       //0x87c
			ULONG IndirectCpuSets : 1;                                        //0x87c
			ULONG RelinquishedCommit : 1;                                     //0x87c
			ULONG HighGraphicsPriority : 1;                                   //0x87c
			ULONG CommitFailLogged : 1;                                       //0x87c
			ULONG ReserveFailLogged : 1;                                      //0x87c
			ULONG SystemProcess : 1;                                          //0x87c
			ULONG HideImageBaseAddresses : 1;                                 //0x87c
			ULONG AddressPolicyFrozen : 1;                                    //0x87c
			ULONG ProcessFirstResume : 1;                                     //0x87c
			ULONG ForegroundExternal : 1;                                     //0x87c
			ULONG ForegroundSystem : 1;                                       //0x87c
			ULONG HighMemoryPriority : 1;                                     //0x87c
			ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
			ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
			ULONG SecurityDomainChanged : 1;                                  //0x87c
			ULONG SecurityFreezeComplete : 1;                                 //0x87c
			ULONG VmProcessorHost : 1;                                        //0x87c
			ULONG VmProcessorHostTransition : 1;                              //0x87c
			ULONG AltSyscall : 1;                                             //0x87c
			ULONG TimerResolutionIgnore : 1;                                  //0x87c
		};
	};
	LONG DeviceAsid;                                                        //0x880
	VOID* SvmData;                                                          //0x888
	EX_PUSH_LOCK SvmProcessLock;                                    //0x890
	ULONGLONG SvmLock;                                                      //0x898
	LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
	ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
	PVOID DiskCounters;                            //0x8b8
	VOID* PicoContext;                                                      //0x8c0
	VOID* EnclaveTable;                                                     //0x8c8
	ULONGLONG EnclaveNumber;                                                //0x8d0
	EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
	ULONG HighPriorityFaultsAllowed;                                        //0x8e0
	PVOID EnergyContext;                       //0x8e8
	VOID* VmContext;                                                        //0x8f0
	ULONGLONG SequenceNumber;                                               //0x8f8
	ULONGLONG CreateInterruptTime;                                          //0x900
	ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
	ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
	ULONGLONG LastAppStateUpdateTime;                                       //0x918
	ULONGLONG LastAppStateUptime : 61;                                        //0x920
	ULONGLONG LastAppState : 3;                                               //0x920
	volatile ULONGLONG SharedCommitCharge;                                  //0x928
	EX_PUSH_LOCK SharedCommitLock;                                  //0x930
	LIST_ENTRY SharedCommitLinks;                                   //0x938
	union
	{
		struct
		{
			ULONGLONG AllowedCpuSets;                                       //0x948
			ULONGLONG DefaultCpuSets;                                       //0x950
		};
		struct
		{
			ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
			ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
		};
	};
	VOID* DiskIoAttribution;                                                //0x958
	VOID* DxgProcess;                                                       //0x960
	ULONG Win32KFilterSet;                                                  //0x968
	PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
	volatile ULONG KTimerSets;                                              //0x978
	volatile ULONG KTimer2Sets;                                             //0x97c
	volatile ULONG ThreadTimerSets;                                         //0x980
	ULONGLONG VirtualTimerListLock;                                         //0x988
	struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
	union
	{
		WNF_STATE_NAME WakeChannel;                                 //0x9a0
		PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
	};
	union
	{
		ULONG MitigationFlags;                                              //0x9d0
		struct
		{
			ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
			ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
			ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
			ULONG DisallowStrippedImages : 1;                                 //0x9d0
			ULONG ForceRelocateImages : 1;                                    //0x9d0
			ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
			ULONG StackRandomizationDisabled : 1;                             //0x9d0
			ULONG ExtensionPointDisable : 1;                                  //0x9d0
			ULONG DisableDynamicCode : 1;                                     //0x9d0
			ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
			ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
			ULONG AuditDisableDynamicCode : 1;                                //0x9d0
			ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
			ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
			ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
			ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
			ULONG DisableNonSystemFonts : 1;                                  //0x9d0
			ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
			ULONG PreferSystem32Images : 1;                                   //0x9d0
			ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
			ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
			ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
			ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
			ULONG SignatureMitigationOptIn : 1;                               //0x9d0
			ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
			ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
			ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
			ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
			ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
			ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
			ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
			ULONG IsolateSecurityDomain : 1;                                  //0x9d0
		} MitigationFlagsValues;                                            //0x9d0
	};
	union
	{
		ULONG MitigationFlags2;                                             //0x9d4
		struct
		{
			ULONG EnableExportAddressFilter : 1;                              //0x9d4
			ULONG AuditExportAddressFilter : 1;                               //0x9d4
			ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
			ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
			ULONG EnableRopStackPivot : 1;                                    //0x9d4
			ULONG AuditRopStackPivot : 1;                                     //0x9d4
			ULONG EnableRopCallerCheck : 1;                                   //0x9d4
			ULONG AuditRopCallerCheck : 1;                                    //0x9d4
			ULONG EnableRopSimExec : 1;                                       //0x9d4
			ULONG AuditRopSimExec : 1;                                        //0x9d4
			ULONG EnableImportAddressFilter : 1;                              //0x9d4
			ULONG AuditImportAddressFilter : 1;                               //0x9d4
			ULONG DisablePageCombine : 1;                                     //0x9d4
			ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
			ULONG CetUserShadowStacks : 1;                                    //0x9d4
			ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
			ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
			ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
			ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
			ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
		} MitigationFlags2Values;                                           //0x9d4
	};
	VOID* PartitionObject;                                                  //0x9d8
	ULONGLONG SecurityDomain;                                               //0x9e0
	ULONGLONG ParentSecurityDomain;                                         //0x9e8
	VOID* CoverageSamplerContext;                                           //0x9f0
	VOID* MmHotPatchContext;                                                //0x9f8
	RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
	EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
}EPROCESS, * PEPROCESS;

typedef struct _STRING32 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG  Buffer;
} STRING32;
typedef STRING32* PSTRING32;

typedef STRING32 UNICODE_STRING32;
typedef UNICODE_STRING32* PUNICODE_STRING32;

//0x10 bytes (sizeof)
typedef struct _UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x8
}UNICODE_STRING, * PUNICODE_STRING;

#pragma pack(push,4)

//0x10 bytes (sizeof)
typedef struct _EWOW64PROCESS
{
	VOID* Peb;                                                              //0x0
	USHORT Machine;                                                         //0x8
}EWOW64PROCESS;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	ULONG SsHandle;                                                         //0x8
	LIST_ENTRY32 InLoadOrderModuleList;										//0xc
	LIST_ENTRY32 InMemoryOrderModuleList;									//0x14
	LIST_ENTRY32 InInitializationOrderModuleList;							//0x1c
	ULONG EntryInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	ULONG ShutdownThreadId;                                                 //0x2c
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;											//0x0
	LIST_ENTRY32 InMemoryOrderLinks;										//0x8
	LIST_ENTRY32 InInitializationOrderLinks;								//0x10
	ULONG DllBase;                                                          //0x18
	ULONG EntryPoint;                                                       //0x1c
	ULONG SizeOfImage;                                                      //0x20
	UNICODE_STRING32 FullDllName;											//0x24
	UNICODE_STRING32 BaseDllName;											//0x2c
	ULONG Flags;                                                            //0x34
	USHORT LoadCount;                                                       //0x38
	USHORT TlsIndex;                                                        //0x3a
	union
	{
		LIST_ENTRY32 HashLinks;												//0x3c
		struct
		{
			ULONG SectionPointer;                                           //0x3c
			ULONG CheckSum;                                                 //0x40
		};
	};
	union
	{
		ULONG TimeDateStamp;                                                //0x44
		ULONG LoadedImports;                                                //0x44
	};
	ULONG EntryPointActivationContext;										//0x48
	ULONG PatchInformation;                                                 //0x4c
	LIST_ENTRY32 ForwarderLinks;											//0x50
	LIST_ENTRY32 ServiceTagLinks;											//0x58
	LIST_ENTRY32 StaticLinks;												//0x60
	ULONG ContextInformation;                                               //0x68
	ULONG OriginalBase;                                                     //0x6c
	LARGE_INTEGER LoadTime;													//0x70
}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsLegacyProcess : 1;                                        //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR SpareBits : 3;                                              //0x3
		};
	};
	ULONG Mutant;                                                           //0x4
	ULONG ImageBaseAddress;                                                 //0x8
	ULONG Ldr;																//0xc
}PEB32, * PPEB32;

#pragma pack(pop)

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	VOID* EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;                                    //0x0
	LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG64 SizeOfImage;                                                      //0x40
	UNICODE_STRING FullDllName;                                     //0x48
	UNICODE_STRING BaseDllName;                                     //0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	USHORT TlsIndex;                                                        //0x6e
	union
	{
		LIST_ENTRY HashLinks;                                       //0x70
		struct
		{
			VOID* SectionPointer;                                           //0x70
			ULONG CheckSum;                                                 //0x78
		};
	};
	union
	{
		ULONG TimeDateStamp;                                                //0x80
		VOID* LoadedImports;                                                //0x80
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* PatchInformation;                                                 //0x90
	LIST_ENTRY ForwarderLinks;                                      //0x98
	LIST_ENTRY ServiceTagLinks;                                     //0xa8
	LIST_ENTRY StaticLinks;                                         //0xb8
	VOID* ContextInformation;                                               //0xc8
	ULONGLONG OriginalBase;                                                 //0xd0
	LARGE_INTEGER LoadTime;                                          //0xd8
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB
{
	ULONG64 x;
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	PEB_LDR_DATA* Ldr;														 //0x18
}PEB, * PPEB;
