/* SPDX-License-Identifier: GPL-2.0-only */
/* Independent byte expectations and recovery negatives, not a NAND simulator. */
#include <assert.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include "airoha_bmt_write.h"
#include "part.h"

/* A 4096-block part keeps the version 3 journal record (pool pinned at 250);
 * any other part writes version 4, which carries system_blocks. */
#define V3 (PART_TOTAL == 4096)
#define LO(v) ((unsigned char)((v) & 255))
#define HI(v) ((unsigned char)((v) >> 8))

static void hash(const unsigned char *p, unsigned int len, unsigned char out[32])
{ assert(SHA256(p, len, out)); }
static void used(struct airoha_bmt_intent *r, unsigned block)
{ unsigned i = block - PART_SYS; r->free_pool[i / 8] &= ~(1u << (i % 8)); }
static void le32(unsigned char *p, unsigned v)
{ p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static struct airoha_bmt table, scratch, old;
static unsigned char page[PART_PAGE], saved[PART_PAGE], check[PART_PAGE];

static void base(void)
{
	static const unsigned short bad[] = {5, 11, 20, 40, 100};
	assert(!airoha_bmt_set_geometry(&table, PART_TOTAL, PART_POOL));
	table.bbt_loaded = table.bmt_loaded = table.bbt_ascending = 1;
	table.bbt_size = 5;
	memcpy(table.bbt_entries, bad, sizeof bad);
	table.bmt_size = 1;
	table.bmt_from[0] = 52;
	table.bmt_to[0] = PART_SYS + 1;
}

static void bytes(void)
{
	/* Checksum: version + size + the entry bytes, which are 52 -> SYS+1. */
	static const unsigned char bmt_head[24] = {
		'B','M','T',1,255,1,LO(1+1+52+LO(PART_SYS+1)+HI(PART_SYS+1)),
		255,255,255,255,255,255,255,255,255,
		255,255,255,255,52,0,LO(PART_SYS+1),HI(PART_SYS+1),
	};
	static const unsigned char bbt_head[22] = {
		'R','A','W','B',182,0,0,0,1,5,255,255,5,0,11,0,20,0,40,0,100,0,
	};
	base();
	assert(!airoha_bmt_encode(&table, page, sizeof page));
	assert(!memcmp(page, bmt_head, sizeof bmt_head));
	/* One zeroed entry per pool block, as the vendor writes; 0xff beyond. */
	for (unsigned i = sizeof bmt_head; i < PART_BMT_END; i++) assert(!page[i]);
	for (unsigned i = PART_BMT_END; i < sizeof page; i++) assert(page[i] == 255);
	assert(!airoha_bbt_encode(&table, page, sizeof page));
	assert(!memcmp(page, bbt_head, sizeof bbt_head));
	for (unsigned i = sizeof bbt_head; i < 512; i++) assert(!page[i]);
	for (unsigned i = 512; i < sizeof page; i++) assert(page[i] == 255);
	assert(!airoha_bmt_set_geometry(&scratch, PART_TOTAL, PART_POOL));
	assert(!airoha_bmt_parse_bbt(&scratch, page, sizeof page));
	assert(!airoha_bmt_encode(&table, page, sizeof page));
	assert(!airoha_bmt_parse_bmt(&scratch, page, sizeof page));
	assert(airoha_bmt_translate(&scratch, 48) == PART_SYS + 1);
	/* The same bytes do not validate at any other pool's extent. */
	assert(!airoha_bmt_set_geometry(&scratch, PART_TOTAL, PART_POOL));
	if (PART_POOL < 250 && PART_POOL < PART_TOTAL / 8) {
		assert(!airoha_bmt_set_geometry(&scratch, PART_TOTAL, PART_POOL + 1));
		assert(airoha_bmt_parse_bmt(&scratch, page, sizeof page) == AIROHA_BMT_E_CHECKSUM);
	}
	memcpy(saved, page, sizeof page);
	assert(airoha_bmt_encode(&table, page, 1020) == -EINVAL);
	assert(!memcmp(saved, page, sizeof page));
	puts("canonical vendor bytes and independent checksum/layout expectations: passed");
}

static void replacement(void)
{
	const unsigned end = BMT_WRITE_END, sys = PART_SYS, last = PART_TOTAL - 1;
	base();
	assert(!airoha_bmt_write_validate(&table, 64, end, sys, last));
	assert(!airoha_bmt_replace(&table, 48, sys + 2));
	assert(table.bmt_size == 2 && table.bmt_from[0] == 52 && table.bmt_to[0] == sys + 2);
	assert(table.bmt_from[1] == sys + 1 && table.bmt_to[1] == sys + 1);
	assert(!airoha_bmt_replace(&table, 48, sys + 3));
	assert(table.bmt_size == 3 && table.bmt_from[0] == 52 && table.bmt_to[0] == sys + 3);
	assert(table.bmt_from[2] == sys + 2 && table.bmt_to[2] == sys + 2);
	assert(!airoha_bmt_replace(&table, 49, sys + 4));
	assert(table.bmt_size == 4 && table.bmt_from[3] == 53);
	old = table;
	assert(airoha_bmt_replace(&table, 49, sys + 3) == -EINVAL);
	assert(!memcmp(&old, &table, sizeof table));
	assert(airoha_bmt_write_validate(&table, 64, sys, sys, last) == -EINVAL);
	assert(airoha_bmt_write_validate(&table, 64, end, sys, sys + 3) == -EINVAL);
	table.bmt_from[1] = 52;
	assert(airoha_bmt_write_validate(&table, 64, end, sys, last) == -EINVAL);
	table = old; table.bmt_to[1] = sys + 3;
	assert(airoha_bmt_write_validate(&table, 64, end, sys, last) == -EINVAL);
	table = old; table.bmt_from[1] = 5;
	assert(airoha_bmt_write_validate(&table, 64, end, sys, last) == -EINVAL);
	table = old; table.bmt_from[1] = sys;
	assert(airoha_bmt_write_validate(&table, 64, end, sys, last) == -EINVAL);
	base(); table.bmt_size = PART_POOL;
	for (unsigned i = 0; i < PART_POOL; i++) {
		table.bmt_from[i] = 1000 + i;
		table.bmt_to[i] = sys + i;
	}
	/* Every pool destination is occupied; reusing one is not allocation,
	 * and the table holds no more entries than the pool has blocks. */
	old = table;
	assert(airoha_bmt_replace(&table, 48, sys) == -EINVAL);
	assert(!memcmp(&old, &table, sizeof table));
	table.bmt_size = PART_POOL + 1;
	assert(airoha_bmt_encode(&table, page, sizeof page) == -EINVAL);
	table = old;
	puts("original-key replacement, repeated wear, pool alias and ownership negatives: passed");
}

static void intent_base(struct airoha_bmt_intent *r, int mapped)
{
	base();
	if (!mapped) table.bmt_size = 0;
	memset(r, 0, sizeof *r);
	r->system_blocks = PART_SYS;
	r->operation = AIROHA_INTENT_PROGRAM;
	r->journal_block = PART_SYS + 2;
	r->candidate_block = PART_SYS + 3;
	r->logical_block = 48;
	r->system_key = 52;
	r->old_physical = mapped ? PART_SYS + 1 : 52;
	r->old_table_block = PART_TOTAL - 1;
	r->bbt_block = PART_SYS;
	r->bbt_size = table.bbt_size;
	r->bmt_size = table.bmt_size;
	r->old_mapping_present = mapped;
	part_all_free(r->free_pool);
	used(r, r->bbt_block); used(r, r->old_table_block);
	if (mapped) used(r, r->old_physical);
	assert(!airoha_bmt_encode(&table, page, sizeof page));
	hash(page, AIROHA_BMT_BYTES, r->bmt_digest);
	assert(!airoha_bbt_encode(&table, page, sizeof page));
	hash(page, AIROHA_BBT_BYTES, r->bbt_digest);
	hash((const unsigned char *)"intended block", 14, r->data_digest);
}

static void intents(void)
{
	unsigned corruptions = 0;
	/* Independent fixed header byte positions, including little endian. */
	const unsigned char head[20] = {
		'S','D','R','W','B','0','0',V3 ? '3' : '4', V3 ? 3 : 4, 0, 1, 0,
		LO(PART_SYS+2), HI(PART_SYS+2), LO(PART_SYS+3), HI(PART_SYS+3), 48, 0, 52, 0,
	};
	unsigned char geometry[16];
	le32(geometry, PART_BLOCK); le32(geometry + 4, PART_PAGE);
	le32(geometry + 8, PART_FREE);
	if (V3) le32(geometry + 12, PART_TOTAL);
	else le32(geometry + 12, PART_TOTAL | PART_SYS << 16);
	for (int mapped = 0; mapped <= 1; mapped++) {
		struct airoha_bmt_intent r, decoded, sentinel;
		intent_base(&r, mapped);
		assert(!airoha_bmt_intent_encode(&r, page, sizeof page, hash));
		assert(!memcmp(page, head, sizeof head));
		assert(page[22] == LO(PART_TOTAL-1) && page[23] == HI(PART_TOTAL-1) &&
		       page[24] == LO(PART_SYS) && page[25] == HI(PART_SYS));
		assert(!memcmp(page + 128, geometry, sizeof geometry));
		assert(!airoha_bmt_intent_decode(&decoded, page, sizeof page, hash));
		assert(!memcmp(&r, &decoded, sizeof r));
		assert(!airoha_bmt_intent_match(&r, &table, &scratch, check, hash));
		old = table;
		assert(!airoha_bmt_replace(&table, 48, r.candidate_block));
		assert(!airoha_bmt_intent_match(&r, &table, &scratch, check, hash));
		table.bbt_entries[0] = 6;
		assert(airoha_bmt_intent_match(&r, &table, &scratch, check, hash) == -EINVAL);
		table = old;
		assert(!airoha_bmt_replace(&table, 49, PART_SYS + 4));
		assert(airoha_bmt_intent_match(&r, &table, &scratch, check, hash) == -EINVAL);
		memcpy(saved, page, sizeof page);
		memset(&sentinel, 0xa5, sizeof sentinel);
		for (unsigned i = 0; i < sizeof page; i++) {
			decoded = sentinel;
			page[i] ^= 1;
			assert(airoha_bmt_intent_decode(&decoded, page, sizeof page, hash) < 0);
			assert(!memcmp(&decoded, &sentinel, sizeof decoded));
			page[i] ^= 1;
			corruptions++;
		}
		assert(!memcmp(saved, page, sizeof page));
		/* Re-hashed malicious records still fail semantic validation. */
		page[14] = page[12]; page[15] = page[13]; hash(page, 208, page + 208);
		assert(airoha_bmt_intent_decode(&decoded, page, sizeof page, hash) == -EINVAL);
		memcpy(page, saved, sizeof page);
		page[144] |= 1; /* A forged free bit for the factory BBT is never authority. */
		hash(page, 208, page + 208);
		assert(airoha_bmt_intent_decode(&decoded, page, sizeof page, hash) == -EINVAL);
		/* Earlier versions, and the other current layout, are refused: a
		 * version 3 record off a 4096-block part has no system_blocks, and
		 * a version 4 header over version 3 bytes reads system_blocks 0. */
		for(unsigned version=1;version<=4;version++) {
			if (version == (V3 ? 3u : 4u)) continue;
			memcpy(page, saved, sizeof page);
			page[7] = '0'+version; page[8] = version;
			hash(page, 208, page + 208);
			assert(airoha_bmt_intent_decode(&decoded, page, sizeof page, hash) == -EINVAL);
		}
		/* A record claiming another pool is not this map's. */
		r.system_blocks--;
		assert(airoha_bmt_intent_match(&r, &old, &scratch, check, hash) == -EINVAL);
		r.system_blocks++;
		r.system_key++;
		assert(airoha_bmt_intent_match(&r, &old, &scratch, check, hash) == -EINVAL);
	}
	printf("journal header/hash/padding corruptions rejected without publishing output: %u\n", corruptions);
	puts("old/new mapping recovery with empty/nonempty tables and changed-factory negatives: passed");
}

int main(void)
{
	bytes(); replacement(); intents();
	return 0;
}
