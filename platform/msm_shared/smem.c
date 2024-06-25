/*
 * Copyright (c) 2009, Google Inc.
 * All rights reserved.
 *
 * Copyright (c) 2014-2015, 2017, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the 
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arch/defines.h>
#include <debug.h>
#include <reg.h>
#include <sys/types.h>
#include <platform/iomap.h>
#include <board.h>

#include "smem.h"

#define SZ_4K 4096

static struct smem *smem;
static struct smem_partition_desc smem_global_partition;

#if DYNAMIC_SMEM
uint32_t smem_get_base_addr(void);
#endif

/* Determine smem base address and init global-static smem pointer */
static uint32_t smem_resolve_addr(void)
{
	static uint32_t smem_addr = 0;

	/* Already resolved? */
	if (smem_addr)
		return smem_addr;

#if DYNAMIC_SMEM
	smem_addr = smem_get_base_addr();
#else
	smem_addr = platform_get_smem_base_addr();
#endif
	smem = (struct smem *)smem_addr;

	/* zerofill global partition desc */
	memset(&smem_global_partition, 0, sizeof(struct smem_partition_desc));

	return smem_addr;
}


uint32_t smem_get_sbl_version(void)
{
	smem_resolve_addr();
	if (smem)
		return smem->version_info[SMEM_MASTER_SBL_VERSION_INDEX];
	return 0;
}


const char *hw_platform[] = {
	[HW_PLATFORM_UNKNOWN] = "Unknown",
	[HW_PLATFORM_SURF] = "Surf",
	[HW_PLATFORM_FFA] = "FFA",
	[HW_PLATFORM_FLUID] = "Fluid",
	[HW_PLATFORM_SVLTE] = "SVLTE",
	[HW_PLATFORM_MTP_MDM] = "MDM_MTP_NO_DISPLAY",
	[HW_PLATFORM_MTP] = "MTP",
	[HW_PLATFORM_RCM] = "RCM",
	[HW_PLATFORM_LIQUID] = "Liquid",
	[HW_PLATFORM_DRAGON] = "Dragon",
	[HW_PLATFORM_QRD] = "QRD",
	[HW_PLATFORM_IPC] = "IPC",
	[HW_PLATFORM_HRD] = "HRD",
	[HW_PLATFORM_DTV] = "DTV",
	[HW_PLATFORM_STP] = "STP",
	[HW_PLATFORM_SBC] = "SBC",
	[HW_PLATFORM_ATP] = "ATP",
};

/* DYNAMIC SMEM REGION feature enables LK to dynamically
 * read the SMEM addr info from TCSR register or IMEM location.
 * The first word read, if indicates a MAGIC number, then
 * Dynamic SMEM is assumed to be enabled. Read the remaining
 * SMEM info for SMEM Size and Phy_addr from the other bytes.
 */

#if DYNAMIC_SMEM
uint32_t smem_get_base_addr(void)
{
	struct smem_addr_info *smem_info = NULL;

	smem_info = (struct smem_addr_info *) SMEM_TARG_INFO_ADDR;
	if(smem_info && (smem_info->identifier == SMEM_TARGET_INFO_IDENTIFIER))
		return smem_info->phy_addr;
	else
		return MSM_SHARED_BASE;
}
#endif

/* buf MUST be 4byte aligned, and len MUST be a multiple of 8. */
unsigned smem_read_alloc_entry(smem_mem_type_t type, void *buf, int len)
{
	struct smem_alloc_info *ainfo;
	unsigned *dest = buf;
	unsigned src = 0;
	unsigned size;
	uint32_t smem_addr = smem_resolve_addr();
	void *srcv;
	size_t itemsize = 0;

	if (((len & 0x3) != 0) || (((unsigned)buf & 0x3) != 0)) {
		dprintf(CRITICAL, "smem_read_alloc_entry: buf/len must be aligned\n");
		return 1;
	}

	if (type < SMEM_FIRST_VALID_TYPE || type > SMEM_LAST_VALID_TYPE) {
		dprintf(CRITICAL, "smem_read_alloc_entry: invalid type\n");
		return 1;
	}

	/* TODO: Use smem spinlocks */

	/* check if we're using global partition? */
	if (smem_global_partition.phys_base) {
		srcv = smem_get_private_item(&smem_global_partition, type, &itemsize);
		src = (unsigned)srcv;
		if (itemsize < (unsigned)len) {
			return 1;
		}
	} else {
		ainfo = &smem->alloc_info[type];
		if (readl(&ainfo->allocated) == 0)
			return 1;

		size = readl(&ainfo->size);
		if (size < (unsigned)((len + 7) & ~0x00000007))
			return 1;

		src = smem_addr + readl(&ainfo->offset);
	}

	if (src == 0)
		return 1;

	for (; len > 0; src += 4, len -= 4)
		*(dest++) = readl(src);

	return 0;
}

/* Return a pointer to smem_item with size */
void* smem_get_alloc_entry(smem_mem_type_t type, uint32_t* size)
{
	struct smem_alloc_info *ainfo = NULL;
	uint32_t base_ext = 0;
	uint32_t offset = 0;
	void *ret = NULL;
	uint32_t smem_addr = smem_resolve_addr();

	if (type < SMEM_FIRST_VALID_TYPE || type > SMEM_LAST_VALID_TYPE)
		return ret;

	ainfo = &smem->alloc_info[type];
	if (readl(&ainfo->allocated) == 0)
		return ret;

	*size = readl(&ainfo->size);
	base_ext = readl(&ainfo->base_ext);
	offset = readl(&ainfo->offset);

	if(base_ext)
	{
		ret = (void*)base_ext + offset;
	}
	else
	{
		ret = (void*) smem_addr + offset;
	}

	return ret;
}

void *smem_alloc_entry(smem_mem_type_t type, uint32_t size)
{
	uint32_t smem_addr, remaining, offset;
	struct smem_alloc_info *ainfo;

	smem_addr = smem_resolve_addr();

	if (type < SMEM_FIRST_VALID_TYPE || type > SMEM_LAST_VALID_TYPE)
		return NULL;

	/* TODO: Use smem spinlocks */
	ainfo = &smem->alloc_info[type];
	if (readl(&ainfo->allocated)) {
		dprintf(CRITICAL, "SMEM entry %d is already allocated\n", type);
		return NULL;
	}

	remaining = readl(&smem->heap_info.heap_remaining);
	if (size > remaining) {
		dprintf(CRITICAL, "Not enough space in SMEM for entry %d (size: %u, remaining: %u)\n",
			type, size, remaining);
		return NULL;
	}

	/* Allocate entry in SMEM */
	offset = readl(&smem->heap_info.free_offset);
	writel(offset, &ainfo->offset);
	writel(size, &ainfo->size);

	dsb();
	writel(1, &ainfo->allocated);

	writel(offset + size, &smem->heap_info.free_offset);
	writel(remaining - size, &smem->heap_info.heap_remaining);
	dsb();

	return (void *)(smem_addr + offset);
}

unsigned
smem_read_alloc_entry_offset(smem_mem_type_t type, void *buf, int len,
			     int offset)
{
	struct smem_alloc_info *ainfo;
	unsigned *dest = buf;
	unsigned src = 0;
	unsigned size = len;
	size_t itemsize = 0;
	uint32_t smem_addr = smem_resolve_addr();
	void *srcv;

	if (((len & 0x3) != 0) || (((unsigned)buf & 0x3) != 0)) {
		dprintf(CRITICAL, "smem_read_alloc_entry_offset: buf/len must be aligned\n");
		return 1;
	}

	if (type < SMEM_FIRST_VALID_TYPE || type > SMEM_LAST_VALID_TYPE) {
		dprintf(CRITICAL, "smem_read_alloc_entry_offset: invalid type\n");
		return 1;
	}

	/* check if we're using global partition? */
	if (smem_global_partition.phys_base) {
		srcv = smem_get_private_item(&smem_global_partition, type, &itemsize);
		if (srcv) {
			src = (unsigned)srcv + offset;
		}
	} else {
		ainfo = &smem->alloc_info[type];
		if (readl(&ainfo->allocated) == 0) {
			dprintf(CRITICAL, "smem_read_alloc_entry_offset: type %u is not allocated\n", (uint32_t)type);
			return 1;
		}
		src = smem_addr + readl(&ainfo->offset) + offset;
	}

	if (src == 0)
		return 1;

	for (; size > 0; src += 4, size -= 4)
		*(dest++) = readl(src);

	return 0;
}

size_t smem_get_hw_platform_name(void *buf, uint32 buf_size)
{
	uint32 hw_id;

	if (buf == NULL) {
		dprintf(CRITICAL, "ERROR: buf is NULL\n");
		return 1;
	}

	hw_id = board_hardware_id();
	if (hw_id >= ARRAY_SIZE(hw_platform) || hw_platform[hw_id] == NULL)
		return 1;

	if (buf_size < strlen(hw_platform[hw_id]) + 1)
		return 1;

	return snprintf(buf, strlen(hw_platform[hw_id]) + 1,
		"%s\n", hw_platform[hw_id]);
}

static const uint8_t SMEM_PART_MAGIC[] = { 0x24, 0x50, 0x52, 0x54 };

static bool
smem_validate_partition_header(struct smem_ptable_entry_v12 *entry,
				uint16_t host0, uint16_t host1)
{
	struct smem_partition_header *header;
	uint32_t phys_addr;
	uint32_t size;
	uint32_t smem_addr = smem_resolve_addr();

	phys_addr = smem_addr + entry->offset;
	header = (struct smem_partition_header *)phys_addr;

	if (!header)
		return false;

	if (memcmp(header->magic, SMEM_PART_MAGIC, sizeof(header->magic))) {
		dprintf(CRITICAL, "bad partition magic %4ph\n", header->magic);
		return false;
	}

	if (host0 != header->host0) {
		dprintf(CRITICAL, "bad host0 (%hu != %hu)\n", host0, header->host0);
		return false;
	}
	if (host1 != header->host1) {
		dprintf(CRITICAL, "bad host1 (%hu != %hu)\n", host1, header->host1);
		return false;
	}

	size = header->size;
	if (size != entry->size) {
		dprintf(CRITICAL, "bad partition size (%u != %u)\n", size, entry->size);
		return false;
	}

	if (header->offset_free_uncached > size) {
		dprintf(CRITICAL, "bad partition free uncached (%u > %u)\n", header->offset_free_uncached, size);
		return false;
	}

	return true;
}

static const uint8_t SMEM_PTABLE_MAGIC[] = { 0x24, 0x54, 0x4f, 0x43 }; /* "$TOC" */

struct smem_ptable_v12 *smem_get_ptable_v12(void)
{
	uint32_t ptable_start;
#ifdef MSM_SMEM_REGION_SIZE
	/* All platforms that use smem ptable v12 should have this defined! */
	uint32_t smem_region_size = MSM_SMEM_REGION_SIZE;
#else
	/* For platforms that do not have this defined in platform/iomap.h */
	/* For other platforms this code path is not used anyway, so doesn't matter. */
	/* Some platforms have this region with size 2M, but some have ony 1M. */
	uint32_t smem_region_size = 0x100000;
#endif
	uint32_t smem_addr = smem_resolve_addr();
	struct smem_ptable_v12 *ptable;

	ptable_start = smem_addr + smem_region_size - SZ_4K;
	ptable = (struct smem_ptable_v12 *)ptable_start;

	if (memcmp(ptable->magic, SMEM_PTABLE_MAGIC, sizeof(ptable->magic))) {
		dprintf(CRITICAL, "SMEM_PTABLE_MAGIC doesn't match!\n");
		return NULL;
	}

	if (ptable->version != 1) {
		dprintf(CRITICAL, "Unsupported partition header version %d\n", ptable->version);
		return NULL;
	}

	dprintf(INFO, "Successfully found and validated smem ptable >= V12 with %u entries\n", ptable->num_entries);
	return ptable;
}

#if 0
static void dump_ptable_entry_v12(uint32_t i, struct smem_ptable_entry_v12 *entry)
{
	dprintf(INFO, " entry%d: size=%08x, offset=%08x, flags=%08x\n", i, entry->size, entry->offset, entry->flags);
	dprintf(INFO, " entry%d: host0, 1 = %08x, %08x\n", i, entry->host0, entry->host1);
	dprintf(INFO, " entry%d: cacheline = %08x\n", i, entry->cacheline);
}
#endif

void smem_setup_global_partition(void)
{
	struct smem_ptable_v12 *ptable;
	struct smem_ptable_entry_v12 *entry = NULL;
	uint32_t i;
	bool found = false;
	uint32_t smem_addr = 0;

	if (smem_global_partition.phys_base != 0) {
		dprintf(SPEW, "Already found the global partition\n");
		return;
	}

	smem_addr = smem_resolve_addr();
	ptable = smem_get_ptable_v12();

	// dprintf(INFO, "ptable = %p\n", ptable);
	// ^^ ptable = 0x861ff000 (matches one from Linux)

	for (i = 0; i < ptable->num_entries; i++) {
		entry = &ptable->entry[i];
		/* dump_ptable_entry_v12(i, entry); */

		if (!entry->offset || !entry->size)
			continue;

		if (entry->host0 != SMEM_GLOBAL_HOST)
			continue;

		if (entry->host1 == SMEM_GLOBAL_HOST) {
			dprintf(INFO, "found global part at idx %u\n", i);
			// should be: found global at idx 6
			found = true;
			break;
		}
	}

	if (!found) {
		dprintf(CRITICAL, "Missing entry for global partition\n");
		ASSERT(0);
	}

	found = smem_validate_partition_header(entry, SMEM_GLOBAL_HOST, SMEM_GLOBAL_HOST);
	if (!found) {
		dprintf(CRITICAL, "Invalid partition header got global partition!\n");
		ASSERT(0);
	}

	smem_global_partition.phys_base = smem_addr + entry->offset;
	smem_global_partition.size = entry->size;
	smem_global_partition.cacheline = entry->cacheline;

	dprintf(INFO, "Set up global partition: [%lx size %u], cacheline %u\n",
		smem_global_partition.phys_base,
		smem_global_partition.size,
		smem_global_partition.cacheline);
	// ^^ Set up global partition: [86001000 size 1015808], cacheline 32
}

/* ===== <helpers> ===== */

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
/* @a is a power of 2 value */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))

static void *
phdr_to_last_uncached_entry(struct smem_partition_header *phdr)
{
	void *p = phdr;
	return p + phdr->offset_free_uncached;
}

static struct smem_private_entry *
phdr_to_first_cached_entry(struct smem_partition_header *phdr,
					size_t cacheline)
{
	void *p = phdr;
	struct smem_private_entry *e;
	return p + phdr->size - ALIGN(sizeof(*e), cacheline);
}

static void *
phdr_to_last_cached_entry(struct smem_partition_header *phdr)
{
	void *p = phdr;
	return p + phdr->offset_free_cached;
}

static struct smem_private_entry *
phdr_to_first_uncached_entry(struct smem_partition_header *phdr)
{
	void *p = phdr;
	return p + sizeof(*phdr);
}

static struct smem_private_entry *
uncached_entry_next(struct smem_private_entry *e)
{
	void *p = e;
	return p + sizeof(*e) + e->padding_hdr + e->size;
}

static struct smem_private_entry *
cached_entry_next(struct smem_private_entry *e, size_t cacheline)
{
	void *p = e;
	return p - e->size - ALIGN(sizeof(*e), cacheline);
}

static void *uncached_entry_to_item(struct smem_private_entry *e)
{
	void *p = e;
	return p + sizeof(*e) + e->padding_hdr;
}

static void *cached_entry_to_item(struct smem_private_entry *e)
{
	void *p = e;
	return p - e->size;
}

/* ===== </helpers> ===== */

void *smem_get_private_item(struct smem_partition_desc *part, unsigned item, size_t *size)
{
	struct smem_private_entry *entry, *entry_end;
	struct smem_partition_header *phdr;
	void *item_ptr, *p_end;
	uint32_t padding_data;
	uint32_t e_size;

	phdr = (struct smem_partition_header *)part->phys_base;
	p_end = (void *)phdr + part->size;

	entry = phdr_to_first_uncached_entry(phdr);
	entry_end = phdr_to_last_uncached_entry(phdr);

	while (entry < entry_end) {
		if (entry->canary != SMEM_PRIVATE_CANARY)
			goto invalid_canary;

		if (entry->item == item) {
			if (size != NULL) {
				e_size = entry->size;
				padding_data = entry->padding_data;
				*size = e_size - padding_data;
			}

			item_ptr = uncached_entry_to_item(entry);
			return item_ptr;
		}

		entry = uncached_entry_next(entry);
	}

	if ((void *)entry > p_end)
		return NULL;

	/* Item was not found in the uncached list, search the cached list */

	entry = phdr_to_first_cached_entry(phdr, part->cacheline);
	entry_end = phdr_to_last_cached_entry(phdr);

	if ((void *)entry < (void *)phdr || (void *)entry_end > p_end)
		return NULL;

	while (entry > entry_end) {
		if (entry->canary != SMEM_PRIVATE_CANARY)
			goto invalid_canary;

		if (entry->item == item) {
			if (size != NULL) {
				e_size = entry->size;
				padding_data = entry->padding_data;
				*size = e_size - padding_data;
			}

			item_ptr = cached_entry_to_item(entry);
			return item_ptr;
		}

		entry = cached_entry_next(entry, part->cacheline);
	}

	if ((void *)entry < (void *)phdr)
		return NULL;

	return NULL;

invalid_canary:
	dprintf(CRITICAL, "Found invalid canary in hosts %hu:%hu partition\n",
			phdr->host0, phdr->host1);
	return NULL;
}
