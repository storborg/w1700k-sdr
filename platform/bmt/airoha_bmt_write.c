// SPDX-License-Identifier: GPL-2.0-only
#include "airoha_bmt_write.h"
#if defined(AIROHA_BMT_HOST)
#include <errno.h>
#else
#include <linux/errno.h>
#endif

/* Version 3 records predate measured pools: they carry the total as a u32
 * and imply the pinned pool of a 4096-block part. They are still written for
 * that geometry; every other geometry writes version 4, which carries the
 * total and system_blocks as two u16 in the same place. */
static const airoha_u8 intent_magic_v3[8] = {'S','D','R','W','B','0','0','3'};
static const airoha_u8 intent_magic_v4[8] = {'S','D','R','W','B','0','0','4'};
#define PINNED_TOTAL 4096u
#define PINNED_SYSTEM (PINNED_TOTAL - AIROHA_BMT_MAX_ENTRIES)

static void wr16(airoha_u8 *p, airoha_u32 v) { p[0] = v; p[1] = v >> 8; }
static void wr32(airoha_u8 *p, airoha_u32 v)
{ wr16(p, v); wr16(p + 2, v >> 16); }
static airoha_u32 rd16(const airoha_u8 *p) { return p[0] | (p[1] << 8); }
static airoha_u32 rd32(const airoha_u8 *p)
{ return rd16(p) | (rd16(p + 2) << 16); }

static airoha_u32 pool_of(const struct airoha_bmt *t)
{
	return t->total_blocks - t->system_blocks;
}

static int was_free(const struct airoha_bmt_intent *r, airoha_u32 physical)
{
	airoha_u32 index;
	if (physical < r->system_blocks || physical >= AIROHA_WRITE_TOTAL)
		return 0;
	index = physical - r->system_blocks;
	return (r->free_pool[index / 8] >> (index % 8)) & 1;
}

static int valid_map(const struct airoha_bmt *t)
{
	airoha_u32 i, j;
	if (!t->geometry_set || !t->bbt_loaded || !t->bmt_loaded ||
	    t->total_blocks != AIROHA_WRITE_TOTAL || t->system_blocks >= t->total_blocks ||
	    pool_of(t) > AIROHA_BMT_MAX_ENTRIES ||
	    !t->bbt_ascending || t->bbt_size > AIROHA_BMT_MAX_ENTRIES ||
	    t->bmt_size > pool_of(t))
		return -EINVAL;
	for (i = 0; i < t->bbt_size; i++)
		if (t->bbt_entries[i] >= t->system_blocks ||
		    (i && t->bbt_entries[i] <= t->bbt_entries[i - 1]))
			return -EINVAL;
	for (i = 0; i < t->bmt_size; i++) {
		if (t->bmt_from[i] >= t->total_blocks ||
		    (t->bmt_from[i] >= t->system_blocks && t->bmt_from[i] != t->bmt_to[i]) ||
		    t->bmt_to[i] < t->system_blocks || t->bmt_to[i] >= t->total_blocks)
			return -EINVAL;
		for (j = 0; j < t->bbt_size; j++)
			if (t->bmt_from[i] == t->bbt_entries[j])
				return -EINVAL;
		for (j = 0; j < i; j++)
			if (t->bmt_from[i] == t->bmt_from[j] || t->bmt_to[i] == t->bmt_to[j])
				return -EINVAL;
	}
	return 0;
}

int airoha_bmt_write_validate(const struct airoha_bmt *t, airoha_u32 first,
		airoha_u32 end, airoha_u32 bbt_block, airoha_u32 bmt_block)
{
	airoha_u32 i;
	if (valid_map(t) || first >= end || end > (airoha_u32)airoha_bmt_usable_blocks(t) ||
	    bbt_block < t->system_blocks || bbt_block >= t->total_blocks ||
	    bmt_block < t->system_blocks || bmt_block >= t->total_blocks ||
	    bbt_block == bmt_block)
		return -EINVAL;
	/* Sorted factory shifting is injective below usable_blocks. Unique BMT
	 * keys/destinations preserve that, since destinations lie above system. */
	for (i = 0; i < t->bmt_size; i++)
		if (t->bmt_to[i] == bbt_block || t->bmt_to[i] == bmt_block)
			return -EINVAL;
	return 0;
}

int airoha_bmt_encode(const struct airoha_bmt *t, airoha_u8 *page, airoha_u32 len)
{
	airoha_u32 i, sum, end;
	if (len < AIROHA_WRITE_PAGE || valid_map(t))
		return -EINVAL;
	/* As the vendor writes it: one zeroed entry per pool block, the rest of
	 * the 250-entry area left 0xff, the checksum over the pool's entries. */
	end = AIROHA_BMT_HEADER + 4 * pool_of(t);
	memset(page, 0xff, AIROHA_WRITE_PAGE);
	memcpy(page, "BMT", 3);
	page[3] = 1;
	page[5] = t->bmt_size;
	memset(page + AIROHA_BMT_HEADER, 0, end - AIROHA_BMT_HEADER);
	for (i = 0; i < t->bmt_size; i++) {
		wr16(page + AIROHA_BMT_HEADER + 4 * i, t->bmt_from[i]);
		wr16(page + AIROHA_BMT_HEADER + 4 * i + 2, t->bmt_to[i]);
	}
	sum = 1 + t->bmt_size;
	for (i = AIROHA_BMT_HEADER; i < end; i++)
		sum += page[i];
	page[6] = sum;
	return 0;
}

int airoha_bbt_encode(const struct airoha_bmt *t, airoha_u8 *page, airoha_u32 len)
{
	airoha_u32 i, sum;
	if (len < AIROHA_WRITE_PAGE || valid_map(t))
		return -EINVAL;
	memset(page, 0xff, AIROHA_WRITE_PAGE);
	memcpy(page, "RAWB", 4);
	page[8] = 1;
	page[9] = t->bbt_size;
	memset(page + AIROHA_BBT_HEADER, 0, 500);
	for (i = 0; i < t->bbt_size; i++)
		wr16(page + AIROHA_BBT_HEADER + 2 * i, t->bbt_entries[i]);
	sum = 1 + t->bbt_size;
	for (i = AIROHA_BBT_HEADER; i < AIROHA_BBT_BYTES; i++)
		sum += page[i];
	wr32(page + 4, sum & 0xffff);
	return 0;
}

int airoha_bmt_replace(struct airoha_bmt *t, airoha_u32 logical, airoha_u32 candidate)
{
	airoha_u32 i, key, index, old_physical;
	int shift;
	if (valid_map(t) || logical >= (airoha_u32)airoha_bmt_usable_blocks(t) ||
	    candidate < t->system_blocks || candidate >= t->total_blocks)
		return -EINVAL;
	shift = airoha_bmt_shift(t, logical);
	if (shift < 0)
		return -EINVAL;
	key = logical + shift;
	index = t->bmt_size;
	for (i = 0; i < t->bmt_size; i++) {
		if (t->bmt_to[i] == candidate)
			return -EINVAL; /* no candidate reuse, even for the same key */
		if (t->bmt_from[i] == key)
			index = i;
	}
	/* Every replacement consumes one entry: a new system key, or an ignored
	 * reserve self-entry quarantining the old destination. Stock translation
	 * ignores reserve sources, but its allocator excludes EVERY destination.
	 * Retirement therefore does not depend on erasing/programming a dead block. */
	if (t->bmt_size == pool_of(t))
		return -ENOSPC;
	if (index == t->bmt_size) {
		t->bmt_size++;
	} else {
		old_physical = t->bmt_to[index];
		t->bmt_from[t->bmt_size] = old_physical;
		t->bmt_to[t->bmt_size++] = old_physical;
	}
	t->bmt_from[index] = key;
	t->bmt_to[index] = candidate;
	return 0;
}

static int in_pool(const struct airoha_bmt_intent *r, airoha_u32 block)
{
	return block >= r->system_blocks && block < AIROHA_WRITE_TOTAL;
}

static int valid_intent(const struct airoha_bmt_intent *r)
{
	airoha_u32 pool, i;
	if (r->system_blocks >= AIROHA_WRITE_TOTAL ||
	    AIROHA_WRITE_TOTAL - r->system_blocks > AIROHA_BMT_MAX_ENTRIES)
		return -EINVAL;
	pool = AIROHA_WRITE_TOTAL - r->system_blocks;
	if ((r->operation != AIROHA_INTENT_PROGRAM && r->operation != AIROHA_INTENT_ERASE) ||
	    r->bbt_size > AIROHA_BMT_MAX_ENTRIES || r->bmt_size > pool ||
	    r->old_mapping_present > 1 ||
	    r->bbt_size > r->system_blocks ||
	    r->logical_block >= r->system_blocks - r->bbt_size ||
	    r->system_key >= r->system_blocks ||
	    r->system_key < r->logical_block ||
	    r->system_key - r->logical_block > r->bbt_size ||
	    !in_pool(r, r->candidate_block) || !in_pool(r, r->journal_block) ||
	    !in_pool(r, r->old_table_block) || !in_pool(r, r->bbt_block) ||
	    r->candidate_block == r->journal_block ||
	    r->candidate_block == r->old_table_block || r->candidate_block == r->bbt_block ||
	    r->journal_block == r->old_table_block || r->journal_block == r->bbt_block ||
	    r->old_table_block == r->bbt_block ||
	    r->old_physical == r->candidate_block || r->old_physical == r->journal_block ||
	    r->old_physical == r->old_table_block || r->old_physical == r->bbt_block)
		return -EINVAL;
	if (r->old_mapping_present)
		if (!in_pool(r, r->old_physical) || !r->bmt_size)
			return -EINVAL;
	if (!r->old_mapping_present && r->old_physical != r->system_key)
		return -EINVAL;
	for (i = pool; i < 8 * sizeof(r->free_pool); i++)
		if ((r->free_pool[i / 8] >> (i % 8)) & 1)
			return -EINVAL;
	if (!was_free(r, r->candidate_block) ||
	    !was_free(r, r->journal_block) || was_free(r, r->old_table_block) ||
	    was_free(r, r->bbt_block) || was_free(r, r->old_physical))
		return -EINVAL;
	return 0;
}

int airoha_bmt_intent_encode(const struct airoha_bmt_intent *r,
		airoha_u8 *p, airoha_u32 len, airoha_sha256_fn hash)
{
	int v3 = AIROHA_WRITE_TOTAL == PINNED_TOTAL && r->system_blocks == PINNED_SYSTEM;
	if (len < AIROHA_WRITE_PAGE || !hash || valid_intent(r))
		return -EINVAL;
	memset(p, 0xff, AIROHA_WRITE_PAGE);
	memcpy(p, v3 ? intent_magic_v3 : intent_magic_v4, 8);
	wr16(p + 8, v3 ? 3 : 4);
	wr16(p + 10, r->operation);
	wr16(p + 12, r->journal_block); wr16(p + 14, r->candidate_block);
	wr16(p + 16, r->logical_block); wr16(p + 18, r->system_key);
	wr16(p + 20, r->old_physical); wr16(p + 22, r->old_table_block);
	wr16(p + 24, r->bbt_block); wr16(p + 26, r->bbt_size);
	wr16(p + 28, r->bmt_size); p[30] = r->old_mapping_present;
	memcpy(p + 32, r->bmt_digest, 32);
	memcpy(p + 64, r->bbt_digest, 32);
	memcpy(p + 96, r->data_digest, 32);
	wr32(p + 128, AIROHA_WRITE_BLOCK); wr32(p + 132, AIROHA_WRITE_PAGE);
	wr32(p + 136, AIROHA_WRITE_OOB);
	if (v3) {
		wr32(p + 140, PINNED_TOTAL);
	} else {
		wr16(p + 140, AIROHA_WRITE_TOTAL); wr16(p + 142, r->system_blocks);
	}
	memcpy(p + 144, r->free_pool, 32);
	memcpy(p + 176, r->preimage_digest, 32);
	hash(p, 208, p + 208);
	return 0;
}

int airoha_bmt_intent_decode(struct airoha_bmt_intent *r,
		const airoha_u8 *p, airoha_u32 len, airoha_sha256_fn hash)
{
	struct airoha_bmt_intent decoded;
	airoha_u8 digest[32];
	airoha_u32 i, system;
	if (len < AIROHA_WRITE_PAGE || !hash || p[31] != 0xff ||
	    rd32(p + 128) != AIROHA_WRITE_BLOCK || rd32(p + 132) != AIROHA_WRITE_PAGE ||
	    rd32(p + 136) != AIROHA_WRITE_OOB)
		return -EINVAL;
	if (!memcmp(p, intent_magic_v3, 8) && rd16(p + 8) == 3 &&
	    AIROHA_WRITE_TOTAL == PINNED_TOTAL && rd32(p + 140) == PINNED_TOTAL)
		system = PINNED_SYSTEM;
	else if (!memcmp(p, intent_magic_v4, 8) && rd16(p + 8) == 4 &&
		 rd16(p + 140) == AIROHA_WRITE_TOTAL)
		system = rd16(p + 142);
	else
		return -EINVAL;
	for (i = AIROHA_INTENT_BYTES; i < AIROHA_WRITE_PAGE; i++)
		if (p[i] != 0xff)
			return -EINVAL;
	hash(p, 208, digest);
	if (memcmp(digest, p + 208, 32))
		return -EBADMSG;
	memset(&decoded, 0, sizeof(decoded));
	decoded.system_blocks = system;
	decoded.operation = rd16(p + 10);
	decoded.journal_block = rd16(p + 12); decoded.candidate_block = rd16(p + 14);
	decoded.logical_block = rd16(p + 16); decoded.system_key = rd16(p + 18);
	decoded.old_physical = rd16(p + 20); decoded.old_table_block = rd16(p + 22);
	decoded.bbt_block = rd16(p + 24); decoded.bbt_size = rd16(p + 26);
	decoded.bmt_size = rd16(p + 28); decoded.old_mapping_present = p[30];
	memcpy(decoded.bmt_digest, p + 32, 32);
	memcpy(decoded.bbt_digest, p + 64, 32);
	memcpy(decoded.data_digest, p + 96, 32);
	memcpy(decoded.free_pool, p + 144, 32);
	memcpy(decoded.preimage_digest, p + 176, 32);
	if (valid_intent(&decoded))
		return -EINVAL;
	*r = decoded;
	return 0;
}

int airoha_bmt_intent_match(const struct airoha_bmt_intent *r,
		const struct airoha_bmt *t, struct airoha_bmt *scratch,
		airoha_u8 *page, airoha_sha256_fn hash)
{
	airoha_u8 digest[32];
	airoha_u32 i, index;
	int mapped, shift;
	if (!hash || valid_intent(r) || valid_map(t) || r->bbt_size != t->bbt_size ||
	    r->system_blocks != t->system_blocks)
		return -EINVAL;
	shift = airoha_bmt_shift(t, r->logical_block);
	if (shift < 0 || r->logical_block + shift != r->system_key)
		return -EINVAL;
	airoha_bbt_encode(t, page, AIROHA_WRITE_PAGE);
	hash(page, AIROHA_BBT_BYTES, digest);
	if (memcmp(digest, r->bbt_digest, 32))
		return -EINVAL;
	mapped = airoha_bmt_translate(t, r->logical_block);
	if (mapped != r->old_physical && mapped != r->candidate_block)
		return -EINVAL;
	*scratch = *t;
	if (mapped == r->candidate_block) {
		index = t->bmt_size;
		for (i = 0; i < t->bmt_size; i++)
			if (t->bmt_from[i] == r->system_key)
				index = i;
		if (index == t->bmt_size)
			return -EINVAL;
		if (r->old_mapping_present) {
			/* The only extra row is the old reserve destination's quarantine.
			 * Remove it before reconstructing the canonical original table. */
			if (t->bmt_size != r->bmt_size + 1 ||
			    t->bmt_from[t->bmt_size-1] != r->old_physical ||
			    t->bmt_to[t->bmt_size-1] != r->old_physical)
				return -EINVAL;
			scratch->bmt_size--;
			scratch->bmt_to[index] = r->old_physical;
		} else {
			/* The writer appends new system keys; arbitrary reordering or
			 * unrelated table changes are not this transaction. */
			if (index + 1 != t->bmt_size)
				return -EINVAL;
			scratch->bmt_size--;
		}
	}
	if (scratch->bmt_size != r->bmt_size ||
	    airoha_bmt_encode(scratch, page, AIROHA_WRITE_PAGE))
		return -EINVAL;
	for (i = 0; i < scratch->bmt_size; i++)
		if (was_free(r, scratch->bmt_to[i]))
			return -EINVAL;
	hash(page, AIROHA_BMT_BYTES, digest);
	return memcmp(digest, r->bmt_digest, 32) ? -EINVAL : 0;
}

static int readable(int rc) { return rc >= 0 || rc == -EUCLEAN; }

static int physical_bad(const struct airoha_bmt_flash *io, airoha_u32 block)
{
	airoha_u8 markers[2];
	int rc = io->markers(io->ctx, block, markers);
	if (rc)
		return rc < 0 ? rc : -EIO;
	return markers[0] != 0xff || markers[1] != 0xff;
}

static int find_selected(struct airoha_bmt *t, const struct airoha_bmt_flash *io,
		airoha_u8 *page, airoha_u32 *selected)
{
	airoha_u32 block;
	int rc;
	for (block = t->total_blocks; block-- > t->system_blocks;) {
		rc = physical_bad(io, block);
		if (rc < 0)
			return rc;
		if (rc)
			continue;
		rc = io->read_page(io->ctx, block, 0, page);
		if (!readable(rc))
			continue; /* stock also skips an unreadable table page */
		if (!airoha_bmt_parse_bmt(t, page, AIROHA_WRITE_PAGE)) {
			*selected = block;
			return 0;
		}
	}
	return -ENOENT;
}

/* Only for an initially-free metadata retry candidate. Erasing first both
 * removes any checksum-valid torn page and resets the page program budget.
 * The controller's erase status is authoritative; the following marker write
 * and readback are the verification boundary. */
static int discard_metadata(const struct airoha_bmt_flash *io, airoha_u32 block)
{
	int rc = io->erase(io->ctx, block);
	if (rc)
		return rc < 0 ? rc : -EIO;
	/* Readback decides whether even a failed marker call actually retired it. */
	io->retire(io->ctx, block);
	rc = physical_bad(io, block);
	return rc == 1 ? 0 : (rc < 0 ? rc : -EIO);
}

static int consume_ticket(const struct airoha_bmt_flash *io,
		const struct airoha_bmt_intent *r, airoha_u32 new_table,
		airoha_u8 *expected, airoha_u8 *actual)
{
	airoha_u32 page, used = 0;
	int rc;
	/* A torn ticket counts, including one whose ECC cannot be read. Inspect
	 * RAW erased state, not an ECC-decoded/all-FF approximation. */
	for (page = 1; page <= AIROHA_RETIRE_ATTEMPTS; page++) {
		rc = io->erased(io->ctx, r->journal_block, page);
		if (rc < 0)
			return rc;
		if (!rc)
			used = page;
	}
	if (used == AIROHA_RETIRE_ATTEMPTS)
		return -EIO;
	page = used + 1;
	memset(expected, 0xff, AIROHA_WRITE_PAGE);
	memcpy(expected, "SDRTICK2", 8);
	wr16(expected + 8, r->old_table_block);
	wr16(expected + 10, new_table);
	wr16(expected + 12, page);
	memcpy(expected + 16, r->bmt_digest, 32);
	io->hash(expected, 48, expected + 48);
	rc = io->program_page(io->ctx, r->journal_block, page, expected);
	if (rc)
		return rc < 0 ? rc : -EIO;
	rc = io->read_page(io->ctx, r->journal_block, page, actual);
	if (!readable(rc))
		return rc;
	return memcmp(expected, actual, AIROHA_WRITE_PAGE) ? -EIO : 0;
}

int airoha_bmt_publish(struct airoha_bmt *t, struct airoha_bmt *scratch,
		const struct airoha_bmt_intent *r, const struct airoha_bmt_flash *io,
		airoha_u32 first, airoha_u32 end, airoha_u8 *expected, airoha_u8 *actual,
		airoha_u32 *selected_table)
{
	struct airoha_bmt other;
	airoha_u32 selected, block, i, high_data, new_table = 0;
	int rc;
	if (!io || !io->hash || !io->read_page || !io->program_page || !io->erase ||
	    !io->erased || !io->markers || !io->retire || !io->verify_image ||
	    t == scratch || expected == actual || valid_map(t) || valid_intent(r) ||
	    r->logical_block < first || r->logical_block >= end)
		return -EINVAL;
	rc = airoha_bmt_intent_encode(r, expected, AIROHA_WRITE_PAGE, io->hash);
	if (rc)
		return rc;
	rc = physical_bad(io, r->journal_block);
	if (rc)
		return rc < 0 ? rc : -EIO;
	rc = io->read_page(io->ctx, r->journal_block, 0, actual);
	if (!readable(rc))
		return rc;
	if (memcmp(expected, actual, AIROHA_WRITE_PAGE))
		return -EBADMSG; /* never publish from an undurable or different record */
	rc = io->verify_image(io->ctx, r);
	if (rc)
		return rc < 0 ? rc : -EIO;
	rc = physical_bad(io, r->candidate_block);
	if (rc)
		return rc < 0 ? rc : -EIO;
	rc = find_selected(t, io, actual, &selected);
	if (rc)
		return rc;
	if (airoha_bmt_write_validate(t, first, end, r->bbt_block, selected) ||
	    airoha_bmt_intent_match(r, t, scratch, expected, io->hash))
		return -EINVAL;
	/* User data must stay BELOW the selected BMT. Otherwise a later data
	 * program, or a torn erase retiring its old replacement, could fabricate
	 * a higher-priority BMT page. Do not consume the last metadata headroom. */
	high_data = r->candidate_block > r->journal_block ? r->candidate_block : r->journal_block;
	if (r->old_physical > high_data)
		high_data = r->old_physical;
	for (i = 0; i < t->bmt_size; i++)
		if (t->bmt_to[i] > high_data)
			high_data = t->bmt_to[i];
	if (airoha_bmt_translate(t, r->logical_block) == r->candidate_block) {
		if (selected <= high_data)
			return -EUCLEAN;
		*selected_table = selected;
		return 0;
	}
	if (selected != r->old_table_block)
		return -EINVAL;
	*scratch = *t;
	rc = airoha_bmt_replace(scratch, r->logical_block, r->candidate_block);
	if (rc)
		return rc;
	rc = airoha_bmt_encode(scratch, expected, AIROHA_WRITE_PAGE);
	if (rc)
		return rc;
	/* The immutable free-pool snapshot is necessary on recovery: it identifies
	 * which partially written lower candidates this transaction can erase.
	 * Unknown pre-existing pool bytes are never an allocation license. */
	for (block = selected; block-- > t->system_blocks;) {
		if (block <= high_data)
			break;
		rc = physical_bad(io, block);
		if (rc < 0)
			return rc;
		if (rc)
			continue;
		rc = io->read_page(io->ctx, block, 0, actual);
		if (!was_free(r, block) || block == r->candidate_block || block == r->journal_block) {
			/* Even a live data block can happen to look like a valid BMT.
			 * Never descend below an unowned selector candidate and then
			 * retire the higher old table: stock would select that candidate. */
			if (!readable(rc))
				return rc;
			other = *t;
			if (!airoha_bmt_parse_bmt(&other, actual, AIROHA_WRITE_PAGE))
				return -EUCLEAN;
			continue;
		}
		if (readable(rc) && !memcmp(expected, actual, AIROHA_WRITE_PAGE)) {
			new_table = block; /* a verified write interrupted before retirement */
			break;
		}
		rc = io->erase(io->ctx, block);
		if (rc) {
			rc = discard_metadata(io, block);
			if (rc)
				return rc;
			continue;
		}
		rc = io->program_page(io->ctx, block, 0, expected);
		if (!rc) {
			rc = io->read_page(io->ctx, block, 0, actual);
			if (readable(rc) && !memcmp(expected, actual, AIROHA_WRITE_PAGE)) {
				new_table = block;
				break;
			}
		}
		rc = discard_metadata(io, block);
		if (rc)
			return rc;
	}
	if (!new_table)
		return -ENOSPC;
	rc = consume_ticket(io, r, new_table, expected, actual);
	if (rc)
		return rc;
	/* Never call the vendor markbad helper: it erases the old table first. */
	io->retire(io->ctx, selected);
	rc = physical_bad(io, selected);
	if (rc != 1)
		return rc < 0 ? rc : -EIO;
	rc = find_selected(t, io, actual, &selected);
	if (rc)
		return rc;
	if (selected != new_table ||
	    airoha_bmt_intent_match(r, t, scratch, expected, io->hash) ||
	    airoha_bmt_translate(t, r->logical_block) != r->candidate_block)
		return -EIO;
	*selected_table = selected;
	return 0;
}
