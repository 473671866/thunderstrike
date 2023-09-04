#pragma once

/*----------------------------------------าณฑํ-------------------------------------------------*/
//PML4E
union HardwarePml4e
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 present : 1;
		unsigned __int64 write : 1;
		unsigned __int64 supervisor : 1;
		unsigned __int64 page_level_write_through : 1;
		unsigned __int64 page_level_cache_disable : 1;
		unsigned __int64 accessed : 1;
		unsigned __int64 reserved1 : 1;
		unsigned __int64 must_be_zero : 1;
		unsigned __int64 ignored_1 : 3;
		unsigned __int64 restart : 1;
		unsigned __int64 page_frame_number : 36;
		unsigned __int64 reserved2 : 4;
		unsigned __int64 ignored_2 : 11;
		unsigned __int64 execute_disable : 1;
	}fields;
};
static_assert(sizeof(HardwarePml4e) == 8, "Size check");

//PDPTE
union HardwarePdpte
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64  present : 1;
		unsigned __int64  write : 1;
		unsigned __int64  supervisor : 1;
		unsigned __int64  page_level_write_through : 1;
		unsigned __int64  page_level_cache_disable : 1;
		unsigned __int64  accessed : 1;
		unsigned __int64  reserved1 : 1;
		unsigned __int64  large_page : 1;
		unsigned __int64  ignored_1 : 3;
		unsigned __int64  restart : 1;
		unsigned __int64  page_frame_number : 36;
		unsigned __int64  reserved2 : 4;
		unsigned __int64  ignored_2 : 11;
		unsigned __int64  execute_disable : 1;
	}fields;
};
static_assert(sizeof(HardwarePdpte) == 8, "Size check");

//PDE
union HardwarePde
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 valid : 1;               //!< [0]
		unsigned __int64 write : 1;               //!< [1]
		unsigned __int64 owner : 1;               //!< [2]
		unsigned __int64 write_through : 1;       //!< [3]     PWT
		unsigned __int64 cache_disable : 1;       //!< [4]     PCD
		unsigned __int64 accessed : 1;            //!< [5]
		unsigned __int64 dirty : 1;               //!< [6]
		unsigned __int64 large_page : 1;          //!< [7]     PAT
		unsigned __int64 global : 1;              //!< [8]
		unsigned __int64 copy_on_write : 1;       //!< [9]
		unsigned __int64 prototype : 1;           //!< [10]
		unsigned __int64 reserved0 : 1;           //!< [11]
		unsigned __int64 page_frame_number : 36;  //!< [12:47]
		unsigned __int64 reserved1 : 4;           //!< [48:51]
		unsigned __int64 software_ws_index : 11;  //!< [52:62]
		unsigned __int64 no_execute : 1;          //!< [63]
	}fields;
};
static_assert(sizeof(HardwarePde) == 8, "Size check");

//PTE
typedef HardwarePde HardwarePte;
/*----------------------------------------าณฑํ-------------------------------------------------*/

#define AddressPageDircetory(address) (address & (~0xfff))

typedef union
{
	struct
	{
		unsigned __int64  reserved1 : 3;
		unsigned __int64  page_level_write_through : 1;
		unsigned __int64  page_level_cache_disable : 1;
		unsigned __int64  reserved2 : 7;
		unsigned __int64  address_of_page_directory : 36;
		unsigned __int64  reserved3 : 16;
	};
	unsigned __int64  flags;
} Ia32Cr3;
static_assert(sizeof(Ia32Cr3) == 8, "Size check");
