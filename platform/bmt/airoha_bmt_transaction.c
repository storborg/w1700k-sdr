// SPDX-License-Identifier: GPL-2.0-only
#include "airoha_bmt_transaction.h"
#if defined(AIROHA_BMT_HOST)
#include <errno.h>
#else
#include <linux/errno.h>
#endif

static int readable(int rc) { return rc >= 0 || rc == -EUCLEAN; }
static int all_ff(const airoha_u8 *p, airoha_u32 n)
{ while (n--) if (*p++ != 255) return 0; return 1; }
/* Reserve indices count from the measured system_blocks. */
#define SYSTEM(w) ((airoha_u32)(w)->map->system_blocks)
#define POOL(w) (AIROHA_WRITE_TOTAL - SYSTEM(w))
static int free_bit(const struct airoha_bmt_intent *r, airoha_u32 b)
{
	airoha_u32 i = b - r->system_blocks;
	return b >= r->system_blocks && b < AIROHA_WRITE_TOTAL &&
	       ((r->free_pool[i/8] >> (i%8)) & 1);
}
static void role(struct airoha_bmt_transaction *w, airoha_u32 b, airoha_u8 value)
{ if (b >= SYSTEM(w) && b < AIROHA_WRITE_TOTAL) w->pool[b-SYSTEM(w)] = value; }

static int bad(struct airoha_bmt_transaction *w, airoha_u32 b)
{
	airoha_u8 marker[2];
	int rc = w->io.metadata.markers(w->io.metadata.ctx, b, marker);
	if (rc) return rc < 0 ? rc : -EIO;
	return marker[0] != 255 || marker[1] != 255;
}
static int blank(struct airoha_bmt_transaction *w, airoha_u32 b)
{
	airoha_u32 p;
	int rc;
	for (p=0; p<AIROHA_WRITE_PAGES; p++) {
		rc = w->io.metadata.erased(w->io.metadata.ctx, b, p);
		if (rc != 1) return rc < 0 ? rc : 0;
	}
	return 1;
}
static int erase_checked(struct airoha_bmt_transaction *w, airoha_u32 b)
{
	int rc = w->io.metadata.erase(w->io.metadata.ctx, b);
	return rc ? (rc < 0 ? rc : -EIO) : 0;
}

static int read_image(struct airoha_bmt_transaction *w, airoha_u32 b,
		airoha_u32 key, airoha_u8 *image, airoha_u8 digest[32])
{
	airoha_u32 p, backref;
	int rc;
	for (p=0; p<AIROHA_WRITE_PAGES; p++) {
		airoha_u8 *data = image + p*AIROHA_IMAGE_STRIDE;
		rc = w->io.read_data(w->io.metadata.ctx,b,p,data,data+AIROHA_WRITE_PAGE);
		if (!readable(rc)) return rc;
		if (rc) w->corrected_reads++;
		backref = data[AIROHA_WRITE_PAGE] | (data[AIROHA_WRITE_PAGE+1] << 8);
		if (backref != 0xffff && backref != key) return -EOPNOTSUPP;
		data[AIROHA_WRITE_PAGE] = data[AIROHA_WRITE_PAGE+1] = 255;
	}
	w->io.metadata.hash(image,AIROHA_IMAGE_BYTES,digest);
	return 0;
}

static int pub_read(void *ctx, airoha_u32 b, airoha_u32 p, airoha_u8 *data)
{ struct airoha_bmt_transaction *w=ctx; return w->io.metadata.read_page(w->io.metadata.ctx,b,p,data); }
static int pub_program(void *ctx, airoha_u32 b, airoha_u32 p, const airoha_u8 *data)
{
	struct airoha_bmt_transaction *w=ctx;
	role(w,b,b==w->journal_block ? AIROHA_POOL_JOURNAL : AIROHA_POOL_TABLE);
	return w->io.metadata.program_page(w->io.metadata.ctx,b,p,data);
}
static int pub_erase(void *ctx, airoha_u32 b)
{
	struct airoha_bmt_transaction *w=ctx;
	role(w,b,AIROHA_POOL_UNKNOWN);
	return w->io.metadata.erase(w->io.metadata.ctx,b);
}
static int pub_erased(void *ctx, airoha_u32 b, airoha_u32 p)
{ struct airoha_bmt_transaction *w=ctx; return w->io.metadata.erased(w->io.metadata.ctx,b,p); }
static int pub_markers(void *ctx, airoha_u32 b, airoha_u8 out[2])
{
	struct airoha_bmt_transaction *w=ctx;
	int rc=w->io.metadata.markers(w->io.metadata.ctx,b,out);
	if (!rc && (out[0]!=255 || out[1]!=255)) role(w,b,AIROHA_POOL_BAD);
	return rc;
}
static int pub_retire(void *ctx, airoha_u32 b)
{ struct airoha_bmt_transaction *w=ctx; return w->io.metadata.retire(w->io.metadata.ctx,b); }
static int pub_verify(void *ctx, const struct airoha_bmt_intent *r)
{
	struct airoha_bmt_transaction *w=ctx;
	airoha_u8 digest[32];
	int rc=bad(w,r->candidate_block);
	if (rc) return rc < 0 ? rc : -EIO;
	rc=read_image(w,r->candidate_block,r->system_key,w->verify,digest);
	if (rc) return rc;
	return memcmp(digest,r->data_digest,32) ? -EBADMSG : 0;
}

static int load_journal(struct airoha_bmt_transaction *w)
{
	int rc=bad(w,w->journal_block);
	if (rc) return rc < 0 ? rc : -EIO;
	rc=blank(w,w->journal_block);
	if (rc < 0) return rc;
	w->has_pending=0;
	if (rc) return 0;
	rc=w->io.metadata.read_page(w->io.metadata.ctx,w->journal_block,0,w->actual);
	if (!readable(rc)) return rc;
	rc=airoha_bmt_intent_decode(&w->pending,w->actual,AIROHA_WRITE_PAGE,w->io.metadata.hash);
	if (rc) return rc; /* known journal: never classify torn/corrupt bytes as free */
	if (w->pending.journal_block!=w->journal_block ||
	    w->pending.bbt_block!=w->bbt_block ||
	    w->pending.logical_block<w->first || w->pending.logical_block>=w->end)
		return -EINVAL;
	rc=airoha_bmt_intent_match(&w->pending,w->map,&w->scratch,w->expected,w->io.metadata.hash);
	if (rc) return rc;
	w->has_pending=1;
	return 0;
}

static int inventory(struct airoha_bmt_transaction *w)
{
	airoha_u32 b, i;
	int rc;
	for (b=SYSTEM(w);b<AIROHA_WRITE_TOTAL;b++) {
		role(w,b,AIROHA_POOL_UNKNOWN);
		rc=bad(w,b);
		if (rc<0) return rc;
		if (rc) { role(w,b,AIROHA_POOL_BAD); continue; }
		if (b==w->journal_block) { role(w,b,AIROHA_POOL_JOURNAL); continue; }
		if (b==w->bbt_block || b==w->bmt_block) { role(w,b,AIROHA_POOL_TABLE); continue; }
		for (i=0;i<w->map->bmt_size;i++) if (w->map->bmt_to[i]==b) break;
		if (i<w->map->bmt_size) { role(w,b,AIROHA_POOL_LIVE); continue; }
		if (w->has_pending && b==w->pending.candidate_block) {
			role(w,b,AIROHA_POOL_STAGE); continue;
		}
		rc=blank(w,b);
		if (rc<0) return rc;
		if (rc) { role(w,b,AIROHA_POOL_FREE); continue; }
		rc=w->io.metadata.read_page(w->io.metadata.ctx,b,0,w->actual);
		if (!readable(rc)) {
			if (w->has_pending && free_bit(&w->pending,b)) continue;
			return rc;
		}
		w->scratch=*w->map;
		if (!airoha_bmt_parse_bmt(&w->scratch,w->actual,AIROHA_WRITE_PAGE) ||
		    !airoha_bmt_parse_bbt(&w->scratch,w->actual,AIROHA_WRITE_PAGE))
			role(w,b,AIROHA_POOL_TABLE);
		/* Unknown nonempty storage is quarantined, never presumed abandoned.
		 * A configured journal cannot disappear into this category. */
	}
	return 0;
}

int airoha_bmt_transaction_init(struct airoha_bmt_transaction *w,
		struct airoha_bmt *map, const struct airoha_bmt_data_io *io,
		airoha_u32 first, airoha_u32 end, airoha_u32 bbt_block,
		airoha_u32 bmt_block, airoha_u32 journal_block, airoha_u8 *work)
{
	airoha_u32 i;
	int rc;
	if (!work) return -ENOMEM;
	if (!io->read_data || !io->program_data || !io->metadata.read_page ||
	    !io->metadata.program_page || !io->metadata.erase || !io->metadata.erased ||
	    !io->metadata.markers || !io->metadata.retire || !io->metadata.hash ||
	    airoha_bmt_write_validate(map,first,end,bbt_block,bmt_block) ||
	    journal_block<map->system_blocks || journal_block>=bmt_block ||
	    journal_block==bbt_block)
		return -EINVAL;
	for(i=0;i<map->bmt_size;i++)
		if(map->bmt_to[i]==journal_block || map->bmt_to[i]>=bmt_block) return -EINVAL;
	memset(w,0,sizeof *w);
	w->map=map; w->io=*io; w->first=first; w->end=end;
	w->bbt_block=bbt_block; w->bmt_block=bmt_block; w->journal_block=journal_block;
	w->image=work; w->verify=work+AIROHA_IMAGE_BYTES;
	w->publisher=(struct airoha_bmt_flash){.ctx=w, .read_page=pub_read,
		.program_page=pub_program,.erase=pub_erase,.erased=pub_erased,
		.markers=pub_markers,.retire=pub_retire,.verify_image=pub_verify,
		.hash=io->metadata.hash};
	rc=load_journal(w);
	if (!rc) rc=inventory(w);
	if (!rc && w->has_pending) rc=airoha_bmt_transaction_recover(w);
	if (rc) { w->failed=1; return rc; }
	w->ready=1;
	return 0;
}

/* Clear transaction-owned metadata left by an aborted publication. Only the
 * immutable initial free set is authority, never a guessed signature. */
static int cancel_metadata(struct airoha_bmt_transaction *w)
{
	airoha_u32 b;
	int rc;
	for(b=SYSTEM(w);b<w->pending.old_table_block;b++) {
		if(!free_bit(&w->pending,b) || b==w->journal_block ||
		   b==w->pending.candidate_block || b==w->bmt_block) continue;
		if(w->pool[b-SYSTEM(w)]==AIROHA_POOL_FREE ||
		   w->pool[b-SYSTEM(w)]==AIROHA_POOL_BAD) continue;
		rc=erase_checked(w,b);
		if(rc) return rc;
		role(w,b,AIROHA_POOL_FREE);
	}
	return 0;
}

/* A failed stage has never carried live data. Erase/verify before marking page
 * zero so retries respect NAND program limits. Published old destinations are
 * retired by the BMT itself, without requiring dead media to erase/program. */
static int retire_data(struct airoha_bmt_transaction *w, airoha_u32 b)
{
	int rc=bad(w,b);
	if(rc<0) return rc;
	if(rc) { role(w,b,AIROHA_POOL_BAD); return 0; }
	rc=erase_checked(w,b);
	if(rc) return rc;
	w->io.metadata.retire(w->io.metadata.ctx,b);
	rc=bad(w,b);
	if(rc!=1) return rc<0 ? rc : -EIO;
	role(w,b,AIROHA_POOL_BAD);
	return 0;
}

static int finish(struct airoha_bmt_transaction *w, int mapped)
{
	airoha_u32 stage=w->pending.candidate_block;
	int rc;
	if(mapped) {
		if(w->pending.old_physical>=w->bmt_block) return -EINVAL;
		/* System sources are unreachable through the new primary mapping.
		 * Old reserve destinations also have an ignored self-entry, excluded
		 * by both allocators. Do not require a dead block to erase/program. */
		role(w,w->pending.old_physical,AIROHA_POOL_LIVE);
	} else {
		rc=cancel_metadata(w);
		if(rc) return rc;
	}
	rc=erase_checked(w,w->journal_block);
	if(rc) return rc;
	w->has_pending=0;
	if(mapped) { role(w,stage,AIROHA_POOL_LIVE); return 0; }
	rc=bad(w,stage);
	if(rc<0) return rc;
	if(rc) { role(w,stage,AIROHA_POOL_BAD); return 0; }
	rc=erase_checked(w,stage);
	if(rc) { role(w,stage,AIROHA_POOL_UNKNOWN); return rc; }
	role(w,stage,AIROHA_POOL_FREE);
	return 0;
}

static int publish(struct airoha_bmt_transaction *w)
{
	airoha_u32 selected;
	int rc=airoha_bmt_publish(w->map,&w->scratch,&w->pending,&w->publisher,
		w->first,w->end,w->expected,w->actual,&selected);
	if(rc) return rc;
	role(w,w->pending.old_table_block,AIROHA_POOL_BAD);
	w->bmt_block=selected; role(w,selected,AIROHA_POOL_TABLE);
	w->remaps++;
	return finish(w,1);
}

int airoha_bmt_transaction_recover(struct airoha_bmt_transaction *w)
{
	airoha_u8 digest[32];
	int current, stage_rc, rc;
	if(w->busy) return -EBUSY;
	if(!w->has_pending) return 0;
	w->busy=1;
	current=airoha_bmt_translate(w->map,w->pending.logical_block);
	if(current<0) { rc=-EINVAL; goto out; }
	if(w->pending.operation==AIROHA_INTENT_ERASE) {
		/* The WAL precedes the destructive erase. Retrying erase is
		 * idempotent; only a reported media failure needs publication. */
		rc=w->io.metadata.erase(w->io.metadata.ctx,current);
		if(!rc) { rc=finish(w,current==(int)w->pending.candidate_block); goto out; }
		if(rc!=-EIO && rc!=-EBADMSG) goto out;
		rc=w->io.metadata.erase(w->io.metadata.ctx,w->pending.candidate_block);
		if(!rc) rc=publish(w);
		goto out;
	}
	stage_rc=pub_verify(w,&w->pending);
	if(!stage_rc) {
		/* Completing an unacknowledged write is allowed. This also closes a
		 * partially started metadata publication rather than abandoning it. */
		rc=publish(w);
	} else {
		rc=read_image(w,current,w->pending.system_key,w->verify,digest);
		if(rc) goto out;
		if(current==w->pending.candidate_block) { rc=stage_rc; goto out; }
		if(!memcmp(digest,w->pending.data_digest,32) ||
		   (w->pending.operation==AIROHA_INTENT_PROGRAM &&
		    !memcmp(digest,w->pending.preimage_digest,32))) {
			rc=finish(w,0); if(!rc) w->aborted++;
		} else rc=stage_rc;
	}
	out:
	w->busy=0;
	if(rc) w->failed=1; else { w->recoveries++; w->failed=0; }
	return rc;
}

static int validate_change(struct airoha_bmt_transaction *w, const struct airoha_bmt_change *c)
{
	airoha_u32 i;
	if(c->logical<w->first || c->logical>=w->end) return -EROFS;
	if(c->offset>AIROHA_WRITE_BLOCK || c->length>AIROHA_WRITE_BLOCK-c->offset ||
	   c->oob_offset>AIROHA_WRITE_PAGES*AIROHA_WRITE_OOB ||
	   c->oob_length>AIROHA_WRITE_PAGES*AIROHA_WRITE_OOB-c->oob_offset ||
	   (c->length && !c->data) || (c->oob_length && !c->oob) ||
	   (c->erase && (c->length || c->oob_length))) return -EINVAL;
	for(i=0;i<c->oob_length;i++)
		if((c->oob_offset+i)%AIROHA_WRITE_OOB<2) return -EOPNOTSUPP;
	return 0;
}

static int allocate(struct airoha_bmt_transaction *w)
{
	airoha_u32 n, b, i, high, meta;
	for(n=0;n<POOL(w);n++) {
		i=(w->cursor+n)%POOL(w); b=SYSTEM(w)+i;
		if(w->pool[i]!=AIROHA_POOL_FREE || b>=w->bmt_block || b==w->journal_block) continue;
		high=b>w->journal_block ? b : w->journal_block;
		for(meta=0;meta<w->map->bmt_size;meta++)
			if(w->map->bmt_to[meta]>high) high=w->map->bmt_to[meta];
		for(meta=w->bmt_block;meta-- > high+1;)
			if(w->pool[meta-SYSTEM(w)]==AIROHA_POOL_FREE) break;
		if(meta<=high) continue;
		w->cursor=(i+1)%POOL(w);
		return b;
	}
	return -ENOSPC;
}

static int prepare_record(struct airoha_bmt_transaction *w, const struct airoha_bmt_change *c,
		airoha_u32 stage, const airoha_u8 before[32])
{
	struct airoha_bmt_intent *r=&w->pending;
	airoha_u32 i;
	int source=airoha_bmt_translate(w->map,c->logical), shift=airoha_bmt_shift(w->map,c->logical);
	if(source<0 || shift<0) return -EINVAL;
	memset(r,0,sizeof *r);
	r->system_blocks=w->map->system_blocks;
	r->operation=c->erase ? AIROHA_INTENT_ERASE : AIROHA_INTENT_PROGRAM;
	r->journal_block=w->journal_block; r->candidate_block=stage;
	r->logical_block=c->logical; r->system_key=c->logical+shift; r->old_physical=source;
	r->old_table_block=w->bmt_block; r->bbt_block=w->bbt_block;
	r->bbt_size=w->map->bbt_size; r->bmt_size=w->map->bmt_size;
	r->old_mapping_present=(airoha_u32)source!=r->system_key;
	for(i=0;i<POOL(w);i++) if(w->pool[i]==AIROHA_POOL_FREE)
		r->free_pool[i/8]|=1u<<(i%8);
	i=w->journal_block-SYSTEM(w); r->free_pool[i/8]|=1u<<(i%8);
	memcpy(r->preimage_digest,before,32);
	airoha_bmt_encode(w->map,w->expected,AIROHA_WRITE_PAGE);
	w->io.metadata.hash(w->expected,AIROHA_BMT_BYTES,r->bmt_digest);
	airoha_bbt_encode(w->map,w->expected,AIROHA_WRITE_PAGE);
	w->io.metadata.hash(w->expected,AIROHA_BBT_BYTES,r->bbt_digest);
	w->io.metadata.hash(w->image,AIROHA_IMAGE_BYTES,r->data_digest);
	return airoha_bmt_intent_encode(r,w->expected,AIROHA_WRITE_PAGE,w->io.metadata.hash);
}

static int write_journal(struct airoha_bmt_transaction *w)
{
	/* Erase immediately before the WAL write. Controller status replaces a
	 * blank scan of every page; the programmed record is read back below. */
	int rc=erase_checked(w,w->journal_block);
	if(rc) return rc;
	rc=w->io.metadata.program_page(w->io.metadata.ctx,w->journal_block,0,w->expected);
	/* A failed call can still leave a valid record. Keep it for recovery. */
	w->has_pending=1;
	if(rc) return rc<0 ? rc : -EIO;
	rc=w->io.metadata.read_page(w->io.metadata.ctx,w->journal_block,0,w->actual);
	if(!readable(rc)) return rc;
	return memcmp(w->expected,w->actual,AIROHA_WRITE_PAGE) ? -EIO : 0;
}

static int program_image_page(struct airoha_bmt_transaction *w, airoha_u32 b,
		airoha_u32 page, airoha_u32 *written, airoha_u32 *oobwritten)
{
	airoha_u8 oob[AIROHA_WRITE_OOB];
	const airoha_u8 *data=w->image+page*AIROHA_IMAGE_STRIDE;
	memcpy(oob,data+AIROHA_WRITE_PAGE,AIROHA_WRITE_OOB);
	if(b>=SYSTEM(w)) { oob[0]=w->pending.system_key; oob[1]=w->pending.system_key>>8; }
	*written=*oobwritten=0;
	return w->io.program_data(w->io.metadata.ctx,b,page,data,oob,written,oobwritten);
}

static int stage_image(struct airoha_bmt_transaction *w)
{
	airoha_u32 p, written, oobwritten, b=w->pending.candidate_block;
	int rc=erase_checked(w,b);
	role(w,b,AIROHA_POOL_STAGE);
	if(rc) return rc;
	if(w->pending.operation==AIROHA_INTENT_PROGRAM) for(p=0;p<AIROHA_WRITE_PAGES;p++) {
		/* Page zero supplies the vendor backreference even if its main is FF.
		 * Other entirely empty pages stay erased for subsequent appends. */
		if(p && all_ff(w->image+p*AIROHA_IMAGE_STRIDE,AIROHA_IMAGE_STRIDE)) continue;
		rc=program_image_page(w,b,p,&written,&oobwritten);
		if(rc || written!=AIROHA_WRITE_PAGE || oobwritten!=AIROHA_WRITE_OOB)
			return rc<0 ? rc : -EIO;
	}
	/* Erase status is authoritative. Programmed candidates are read back once. */
	return w->pending.operation==AIROHA_INTENT_ERASE ? 0 : pub_verify(w,&w->pending);
}

static airoha_u32 overlap(airoha_u32 a, airoha_u32 n, airoha_u32 b, airoha_u32 m)
{
	airoha_u32 first=a>b ? a : b, end=a+n<b+m ? a+n : b+m;
	return end>first ? end-first : 0;
}
static int affected(const struct airoha_bmt_change *c, airoha_u32 p)
{
	return overlap(c->offset,c->length,p*AIROHA_WRITE_PAGE,AIROHA_WRITE_PAGE) ||
	       overlap(c->oob_offset,c->oob_length,p*AIROHA_WRITE_OOB,AIROHA_WRITE_OOB);
}

static int apply_original(struct airoha_bmt_transaction *w, const struct airoha_bmt_change *c,
		struct airoha_bmt_progress *done)
{
	airoha_u32 p, written, oobwritten, b=w->pending.old_physical;
	airoha_u8 digest[32];
	int rc;
	if(c->erase) return erase_checked(w,b);
	/* Do not reprogram existing ECC, exceed partial-program budgets, or move
	 * backwards through a used block. A non-erased target page is a remap. */
	for(p=0;p<AIROHA_WRITE_PAGES;p++) if(affected(c,p)) {
		rc=w->io.metadata.erased(w->io.metadata.ctx,b,p);
		if(rc!=1) return rc<0 ? rc : -EIO;
	}
	/* Even an erased early page cannot be programmed after a used later page. */
	for(p=AIROHA_WRITE_PAGES;p-- > 0;) {
		if(affected(c,p)) continue;
		rc=w->io.metadata.erased(w->io.metadata.ctx,b,p);
		if(rc<0) return rc;
		if(!rc) {
			airoha_u32 q;
			for(q=0;q<p;q++) if(affected(c,q)) return -EIO;
			break;
		}
	}
	for(p=0;p<AIROHA_WRITE_PAGES;p++) if(affected(c,p)) {
		rc=program_image_page(w,b,p,&written,&oobwritten);
		if(written>AIROHA_WRITE_PAGE || oobwritten>AIROHA_WRITE_OOB) return -EIO;
		done->data+=overlap(c->offset,c->length,p*AIROHA_WRITE_PAGE,written);
		done->oob+=overlap(c->oob_offset,c->oob_length,p*AIROHA_WRITE_OOB,oobwritten);
		if(rc || written!=AIROHA_WRITE_PAGE || oobwritten!=AIROHA_WRITE_OOB)
			return rc<0 ? rc : -EIO;
	}
	rc=read_image(w,b,w->pending.system_key,w->verify,digest);
	if(rc) return rc;
	return memcmp(digest,w->pending.data_digest,32) ? -EIO : 0;
}

int airoha_bmt_transaction_apply(struct airoha_bmt_transaction *w,
		const struct airoha_bmt_change *c, struct airoha_bmt_progress *done)
{
	airoha_u8 before[32]={0};
	airoha_u32 i, p, col, attempts;
	int source, stage, rc, started=0;
	done->data=done->oob=0;
	if(w->busy) return -EBUSY;
	if(!w->ready || w->failed || w->has_pending) return -EROFS;
	rc=validate_change(w,c); if(rc) return rc;
	if(!c->erase && !c->length && !c->oob_length) return 0;
	w->busy=1;
	source=airoha_bmt_translate(w->map,c->logical);
	if(source<0) { rc=-EINVAL; goto out; }
	if(c->erase) {
		/* Normal erase is one controller operation and no NAND WAL write.
		 * A reset-interrupted erase is idempotently retried by UBI/the caller.
		 * Only a reported media failure enters replacement publication. */
		rc=w->io.metadata.erase(w->io.metadata.ctx,source);
		if(!rc) goto out;
		if(rc!=-EIO && rc!=-EBADMSG) goto out;
		memset(w->image,255,AIROHA_IMAGE_BYTES);
		for(attempts=0;attempts<AIROHA_BMT_MAX_ENTRIES;attempts++) {
			stage=allocate(w); if(stage<0) { rc=stage; goto out; }
			rc=prepare_record(w,c,stage,before); if(rc) goto out;
			started=1; rc=write_journal(w); if(rc) goto out;
			rc=w->io.metadata.erase(w->io.metadata.ctx,stage);
			if(!rc) { rc=publish(w); goto out; }
			if(rc!=-EIO && rc!=-EBADMSG) goto out;
			rc=retire_data(w,stage); if(rc) goto out;
			rc=erase_checked(w,w->journal_block); if(rc) goto out;
			w->has_pending=0;
		}
		rc=-ENOSPC; goto out;
	}
	else {
		int shift=airoha_bmt_shift(w->map,c->logical);
		if(shift<0) { rc=-EINVAL; goto out; }
		rc=read_image(w,source,c->logical+shift,w->image,before);
		if(rc) goto out;
		for(i=0;i<c->length;i++) {
			p=(c->offset+i)/AIROHA_WRITE_PAGE; col=(c->offset+i)%AIROHA_WRITE_PAGE;
			w->image[p*AIROHA_IMAGE_STRIDE+col]=c->data[i];
		}
		for(i=0;i<c->oob_length;i++) {
			p=(c->oob_offset+i)/AIROHA_WRITE_OOB; col=(c->oob_offset+i)%AIROHA_WRITE_OOB;
			w->image[p*AIROHA_IMAGE_STRIDE+AIROHA_WRITE_PAGE+col]=c->oob[i];
		}
	}
	for(attempts=0;attempts<AIROHA_BMT_MAX_ENTRIES;attempts++) {
		stage=allocate(w); if(stage<0) { rc=stage; goto out; }
		rc=prepare_record(w,c,stage,before); if(rc) goto out;
		started=1;
		rc=write_journal(w); if(rc) goto out;
		rc=stage_image(w);
		if(!rc) break;
		if(rc!=-EIO && rc!=-EBADMSG) goto out;
		/* Original has not been touched. Safely retire this failed stage,
		 * then clear its journal before preparing another candidate. */
		rc=retire_data(w,stage); if(rc) goto out;
		rc=erase_checked(w,w->journal_block); if(rc) goto out;
		w->has_pending=0;
	}
	if(attempts==AIROHA_BMT_MAX_ENTRIES) { rc=-ENOSPC; goto out; }
	rc=apply_original(w,c,done);
	if(rc==-EIO || rc==-EBADMSG) rc=publish(w);
	else if(!rc) rc=finish(w,0);
	if(!rc) { done->data=c->length; done->oob=c->oob_length; }
	out:
	w->busy=0;
	if(rc && started) w->failed=1;
	return rc;
}
