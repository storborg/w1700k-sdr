/* SPDX-License-Identifier: GPL-2.0-only */
/* Shared MTD adapter for the part the image is built for (airoha_bmt_policy.h),
 * included by both persistent bindings. layer holds saved physical callbacks.
 * All entrypoints hold BMT_ENTER/LEAVE; internal callbacks never recurse
 * through public MTD operations. */
#include "airoha_bmt_transaction.h"
#include "airoha_bmt_policy.h"

#define BMT_PAGE AIROHA_WRITE_PAGE
#define BMT_BLOCK AIROHA_WRITE_BLOCK
#define BMT_PAGES AIROHA_WRITE_PAGES
#define BMT_FREE_OOB AIROHA_WRITE_OOB
#define BMT_STRIDE AIROHA_IMAGE_STRIDE
_Static_assert(BMT_PAGES <= 64, "the per-block page bitmaps below are one u64");
_Static_assert(BMT_FREE_OOB == BMT_OOB_BYTES / 32 * 14,
	       "free OOB is 14 bytes of each 16-byte spare section of the first half");

static int bmt_transport_failed;
#define BMT_FAST_FALLBACK 1
#define BMT_FAST_BLOCKS (BMT_FAST_END-BMT_FAST_FIRST)
static u64 fast_known[(BMT_FAST_BLOCKS+63)/64];
static u64 fast_pre_erased[(BMT_FAST_BLOCKS+63)/64];
static u64 fast_programmed_pages[BMT_FAST_BLOCKS];
static signed char fast_highest_page[BMT_FAST_BLOCKS];

static int fast_index(u32 logical)
{
	return logical<BMT_FAST_FIRST || logical>=BMT_FAST_END ?
		-1 : (int)(logical-BMT_FAST_FIRST);
}
static int fast_bit(const u64 *bits,u32 logical)
{
	int bit=fast_index(logical);
	return bit<0 ? 0 : (bits[bit/64]>>(bit%64))&1;
}
static void fast_set_bit(u64 *bits,u32 logical,int value)
{
	int bit=fast_index(logical);
	if(bit<0) return;
	if(value) bits[bit/64]|=1ULL<<(bit%64);
	else bits[bit/64]&=~(1ULL<<(bit%64));
}
static void fast_prepare(u32 logical)
{
	int index=fast_index(logical); if(index<0) return;
	fast_set_bit(fast_known,logical,1);fast_set_bit(fast_pre_erased,logical,1);
	fast_programmed_pages[index]=0;fast_highest_page[index]=-1;
}
static void fast_drop(u32 logical)
{ fast_set_bit(fast_known,logical,0);fast_set_bit(fast_pre_erased,logical,0); }
static void fast_reset(void)
{
	memset(fast_known,0,sizeof fast_known);memset(fast_pre_erased,0,sizeof fast_pre_erased);
	memset(fast_programmed_pages,0,sizeof fast_programmed_pages);
	memset(fast_highest_page,0xff,sizeof fast_highest_page);
}

static int managed_transport(int rc)
{
	/* A manual SPI timeout can leave CS/command completion unknown. No next
	 * command is allowed until reset. DMA/array-ready failures panic earlier. */
	if(rc == -ETIMEDOUT) bmt_transport_failed=1;
	return rc;
}
static int physical_read(struct mtd_info *mtd, loff_t from, struct mtd_oob_ops *ops)
{
	int rc;
	if(bmt_transport_failed) return -EIO;
	rc=managed_transport(layer._read_oob(mtd,from,ops));
	if(ops->retlen!=ops->len || ops->oobretlen!=ops->ooblen)
		return rc<0 ? rc : -EIO;
	return rc;
}
static int physical_write(struct mtd_info *mtd, loff_t to, struct mtd_oob_ops *ops)
{
	if(bmt_transport_failed) return -EIO;
	return managed_transport(layer._write_oob(mtd,to,ops));
}
static loff_t physical_address(u32 block, u32 page)
{ return (loff_t)block*BMT_BLOCK + (loff_t)page*BMT_PAGE; }

static int flash_read(void *ctx,u32 b,u32 p,u8 *data)
{
	struct mtd_oob_ops op={.mode=MTD_OPS_AUTO_OOB,.len=BMT_PAGE,.datbuf=data};
	int rc;
	layer.counters.readback_attempts++;
	rc=physical_read(ctx,physical_address(b,p),&op);
	if(!rc || rc==-EUCLEAN) layer.counters.readback_completed++;
	return rc;
}
static int flash_program(void *ctx,u32 b,u32 p,const u8 *data)
{
	struct mtd_oob_ops op={.mode=MTD_OPS_AUTO_OOB,.len=BMT_PAGE,.datbuf=(u8 *)data};
	int rc;
	layer.counters.program_attempts++;
	rc=physical_write(ctx,physical_address(b,p),&op);
	if(!rc && op.retlen==BMT_PAGE) layer.counters.program_completed++;
	return rc ? rc : (op.retlen==BMT_PAGE ? 0 : -EIO);
}
static int flash_erase(void *ctx,u32 b)
{
	struct erase_info erase={.addr=physical_address(b,0),.len=BMT_BLOCK};
	int rc;
	if(bmt_transport_failed) return -EIO;
	layer.counters.erase_attempts++;
	rc=managed_transport(layer._erase(ctx,&erase));
	if(!rc) layer.counters.erase_completed++;
	return rc;
}
static int flash_markers(void *ctx,u32 b,u8 out[2])
{
	struct mtd_oob_ops op={.mode=MTD_OPS_RAW,.ooblen=2,.oobbuf=out};
	int rc;
	layer.counters.readback_attempts++;
	rc=physical_read(ctx,physical_address(b,0),&op);
	if(!rc) layer.counters.readback_completed++;
	return rc;
}
static int flash_erased(void *ctx,u32 b,u32 p)
{
	/* RAW main data on the SNFI path shows controller bytes, not 0xff, for an
	 * erased page (0x55 has been seen).  Programming uses the
	 * ECC/AUTO view, so its erased admission must use that same view plus every
	 * client-writable OOB byte; factory/worn markers are checked separately. */
	struct mtd_oob_ops op={.mode=MTD_OPS_AUTO_OOB,.len=BMT_PAGE,.ooblen=BMT_FREE_OOB,
		.datbuf=layer.io_page,.oobbuf=layer.io_page+BMT_PAGE};
	unsigned i;
	int rc;
	layer.counters.readback_attempts++;
	rc=physical_read(ctx,physical_address(b,p),&op);
	if(!rc || rc==-EUCLEAN) layer.counters.readback_completed++;
	if(rc<0) return rc;
	for(i=0;i<BMT_STRIDE;i++) if(layer.io_page[i]!=255) return 0;
	return 1;
}
static int flash_retire(void *ctx,u32 b)
{
	u8 marker=0;
	struct mtd_oob_ops op={.mode=MTD_OPS_RAW,.ooboffs=1,.ooblen=1,.oobbuf=&marker};
	int rc;
	layer.counters.markbad_attempts++;
	layer.counters.program_attempts++;
	rc=physical_write(ctx,physical_address(b,0),&op);
	if(!rc && op.oobretlen==1) {
		layer.counters.markbad_completed++;
		layer.counters.program_completed++;
	}
	return rc ? rc : (op.oobretlen==1 ? 0 : -EIO);
}
static int flash_read_data(void *ctx,u32 b,u32 p,u8 *data,u8 *oob)
{
	struct mtd_oob_ops op={.mode=MTD_OPS_AUTO_OOB,.len=BMT_PAGE,.ooblen=BMT_FREE_OOB,
		.datbuf=data,.oobbuf=oob};
	int rc;
	layer.counters.readback_attempts++;
	rc=physical_read(ctx,physical_address(b,p),&op);
	if(!rc || rc==-EUCLEAN) layer.counters.readback_completed++;
	return rc;
}
static int flash_program_data(void *ctx,u32 b,u32 p,const u8 *data,const u8 *oob,
		u32 *written,u32 *oobwritten)
{
	struct mtd_oob_ops op={.mode=MTD_OPS_AUTO_OOB,.len=BMT_PAGE,.ooblen=BMT_FREE_OOB,
		.datbuf=(u8 *)data,.oobbuf=(u8 *)oob};
	int rc;
	*written=*oobwritten=0;
	layer.counters.program_attempts++;
	rc=physical_write(ctx,physical_address(b,p),&op);
	if(op.retlen>BMT_PAGE || op.oobretlen>BMT_FREE_OOB) return -EIO;
	*written=op.retlen; *oobwritten=op.oobretlen;
	if(!rc && op.retlen==BMT_PAGE && op.oobretlen==BMT_FREE_OOB)
		layer.counters.program_completed++;
	return rc;
}

static void managed_free(void)
{
	BMT_FREE(layer.io_page); BMT_FREE(layer.work); BMT_FREE(layer.writer);
	layer.io_page=NULL; layer.work=NULL; layer.writer=NULL;
	fast_reset();
}
static int managed_prepare(struct mtd_info *mtd)
{
	struct airoha_bmt_data_io io={.metadata={.ctx=mtd,.read_page=flash_read,
		.program_page=flash_program,.erase=flash_erase,.erased=flash_erased,
		.markers=flash_markers,.retire=flash_retire,.hash=BMT_SHA256},
		.read_data=flash_read_data,.program_data=flash_program_data};
	int rc;
	if(bmt_transport_failed) return -EIO;
	if(mtd->size!=(u64)BMT_TOTAL_BLOCKS*BMT_BLOCK || mtd->erasesize!=BMT_BLOCK ||
	   mtd->writesize!=BMT_PAGE || mtd->oobsize!=BMT_OOB_BYTES ||
	   mtd->oobavail!=BMT_FREE_OOB || !layer._write_oob || !layer._erase ||
	   !(mtd->flags & MTD_WRITEABLE)) return -EINVAL;
	layer.writer=BMT_ALLOC(sizeof(*layer.writer));
	layer.work=BMT_ALLOC(AIROHA_TRANSACTION_WORK_BYTES);
	/* Two decoded main+free-OOB pages for direct write/readback. */
	layer.io_page=BMT_ALLOC(2*BMT_STRIDE);
	if(!layer.writer || !layer.work || !layer.io_page) { managed_free(); return -ENOMEM; }
	rc=airoha_bmt_transaction_init(layer.writer,&layer.t,&io,BMT_WRITE_FIRST,
		BMT_WRITE_END,layer.bbt_block,layer.bmt_block,BMT_JOURNAL_BLOCK,layer.work);
	if(rc) managed_free(); else fast_reset();
	return rc;
}

static int managed_ready(struct mtd_info *mtd)
{
	return layer.mtd==mtd && layer.writer && !layer.writer->failed &&
	       !bmt_transport_failed ? 0 : -EIO;
}
static int managed_read(struct mtd_info *mtd,loff_t from,struct mtd_oob_ops *ops)
{
	int rc=BMT_ENTER();
	ops->retlen=ops->oobretlen=0;
	if(rc) return rc;
	rc=managed_ready(mtd);
	if(!rc) rc=managed_transport(BMT_READ(mtd,from,ops));
	if(bmt_transport_failed && layer.writer) layer.writer->failed=1;
	BMT_LEAVE(); return rc;
}

/* Validate the ENTIRE request before any destructive step. Public master and
 * partition callers have identical vendor-logical protection. */
static int managed_bounds(loff_t to,size_t len,size_t olen,u32 offs,u32 mode)
{
	u64 first=(u64)BMT_WRITE_FIRST*BMT_BLOCK, end=(u64)BMT_WRITE_END*BMT_BLOCK;
	u64 pages;
	u32 per=mode==MTD_OPS_AUTO_OOB ? BMT_FREE_OOB : BMT_OOB_BYTES;
	if(to<0) return -EINVAL;
	if((u64)to<first || (u64)to>=end || len>end-to) return -EROFS;
	pages=(end-((u64)to & ~(u64)(BMT_PAGE-1)))/BMT_PAGE;
	if(olen && (offs>=per || olen>pages*per-offs)) return -EROFS;
	return 0;
}
static int managed_oob(struct mtd_oob_ops *ops,u32 *auto_off)
{
	u32 col=ops->ooboffs;
	if(ops->mode==MTD_OPS_RAW) return -EOPNOTSUPP;
	if(ops->mode!=MTD_OPS_AUTO_OOB && ops->mode!=MTD_OPS_PLACE_OOB) return -EINVAL;
	if(!ops->ooblen) { *auto_off=0; return 0; }
	if(ops->mode==MTD_OPS_AUTO_OOB) {
		if(col<2 || col>=BMT_FREE_OOB || ops->ooblen>BMT_FREE_OOB-col) return -EOPNOTSUPP;
		*auto_off=col; return 0;
	}
	/* PLACE may name one contiguous free region, excluding the backreference.
	 * Marker/parity/gap writes are refused, never converted into corrected data. */
	if(col>=BMT_OOB_BYTES/2 || col%16<2 || (col<16 && col<4) || ops->ooblen>16-col%16)
		return -EOPNOTSUPP;
	*auto_off=(col/16)*14+col%16-2;
	return 0;
}

static u32 fast_overlap(u32 a,u32 n,u32 b,u32 m)
{
	u32 first=a>b ? a : b, end=a+n<b+m ? a+n : b+m;
	return end>first ? end-first : 0;
}

/* A controller-acknowledged erase in this boot makes one block eligible for
 * direct, ascending first-page programs. Verify each written page exactly once.
 * Any uncertainty falls back to the durable transaction/remap engine. */
static int fast_program(struct mtd_info *mtd,const struct airoha_bmt_change *c,
		struct airoha_bmt_progress *done)
{
	u8 *expected=layer.io_page,*actual=layer.io_page+BMT_STRIDE;
	u32 p,written,oobwritten;
	int index,mapped,shift,rc;
	index=fast_index(c->logical);
	if(index<0 || !fast_bit(fast_known,c->logical)) return BMT_FAST_FALLBACK;
	mapped=map_block(c->logical); shift=airoha_bmt_shift(&layer.t,c->logical);
	if(mapped<0 || shift<0) return -EIO;
	for(p=0;p<BMT_PAGES;p++) {
		u32 data=fast_overlap(c->offset,c->length,p*BMT_PAGE,BMT_PAGE);
		u32 oob=fast_overlap(c->oob_offset,c->oob_length,p*BMT_FREE_OOB,BMT_FREE_OOB);
		u32 start;
		if(!data && !oob) continue;
		if((fast_programmed_pages[index]&(1ULL<<p)) ||
		   (int)p<fast_highest_page[index])
			return BMT_FAST_FALLBACK;
		memset(expected,255,BMT_STRIDE);
		if(data) {
			start=c->offset>p*BMT_PAGE ? c->offset : p*BMT_PAGE;
			memcpy(expected+start-p*BMT_PAGE,c->data+start-c->offset,data);
		}
		if(oob) {
			start=c->oob_offset>p*BMT_FREE_OOB ? c->oob_offset : p*BMT_FREE_OOB;
			memcpy(expected+BMT_PAGE+start-p*BMT_FREE_OOB,c->oob+start-c->oob_offset,oob);
		}
		if(mapped>=layer.t.system_blocks) {
			expected[BMT_PAGE]=c->logical+shift;
			expected[BMT_PAGE+1]=(c->logical+shift)>>8;
		}
		rc=flash_program_data(mtd,mapped,p,expected,expected+BMT_PAGE,
			&written,&oobwritten);
		if(rc || written!=BMT_PAGE || oobwritten!=BMT_FREE_OOB) return rc<0 ? rc : -EIO;
		rc=flash_read_data(mtd,mapped,p,actual,actual+BMT_PAGE);
		if((rc<0 && rc!=-EUCLEAN) || memcmp(expected,actual,BMT_STRIDE)) return -EIO;
		fast_programmed_pages[index]|=1ULL<<p; fast_highest_page[index]=p;
	}
	fast_set_bit(fast_pre_erased,c->logical,0);
	done->data=c->length; done->oob=c->oob_length;
	return 0;
}

static int managed_write(struct mtd_info *mtd,loff_t to,struct mtd_oob_ops *ops)
{
	u32 auto_off;
	int rc=BMT_ENTER();
	ops->retlen=ops->oobretlen=0;
	if(rc) return rc;
	rc=managed_ready(mtd); if(rc) goto out;
	rc=managed_bounds(to,ops->len,ops->ooblen,ops->ooboffs,ops->mode); if(rc) goto out;
	if((ops->len && !ops->datbuf) || (ops->ooblen && !ops->oobbuf)) { rc=-EINVAL; goto out; }
	rc=managed_oob(ops,&auto_off); if(rc) goto out;
	while(ops->retlen<ops->len || ops->oobretlen<ops->ooblen) {
		u32 offset=(u64)to%BMT_BLOCK, span=BMT_BLOCK-offset;
		struct airoha_bmt_progress done;
		struct airoha_bmt_change change={.logical=(u64)to/BMT_BLOCK,.offset=offset,
			.length=min_t(size_t,span,ops->len-ops->retlen),
			.data=ops->datbuf ? ops->datbuf+ops->retlen : NULL,
			.oob_offset=(offset/BMT_PAGE)*BMT_FREE_OOB+auto_off,
			.oob_length=ops->ooblen-ops->oobretlen,
			.oob=ops->oobbuf ? ops->oobbuf+ops->oobretlen : NULL};
		rc=fast_program(mtd,&change,&done);
		if(rc) {
			fast_drop(change.logical);
			rc=airoha_bmt_transaction_apply(layer.writer,&change,&done);
		}
		ops->retlen+=done.data; ops->oobretlen+=done.oob;
		if(rc) break;
		to+=span; auto_off=0;
	}
out:
	BMT_LEAVE(); return rc;
}
static int managed_erase(struct mtd_info *mtd,struct erase_info *erase)
{
	u64 cursor=erase->addr,end;
	int rc=BMT_ENTER();
	if(rc) return rc;
	rc=managed_ready(mtd); if(rc) goto out;
	if(cursor%BMT_BLOCK || erase->len%BMT_BLOCK) { rc=-EINVAL; goto out; }
	if(cursor<(u64)BMT_WRITE_FIRST*BMT_BLOCK || cursor>=(u64)BMT_WRITE_END*BMT_BLOCK ||
	   erase->len>(u64)BMT_WRITE_END*BMT_BLOCK-cursor) { rc=-EROFS; goto out; }
	end=cursor+erase->len;
	while(cursor<end) {
		struct airoha_bmt_change change={.logical=cursor/BMT_BLOCK,.erase=1};
		struct airoha_bmt_progress done;
		if(fast_bit(fast_pre_erased,change.logical)) rc=0;
		else rc=airoha_bmt_transaction_apply(layer.writer,&change,&done);
		if(rc) break;
		fast_prepare(change.logical);
		cursor+=BMT_BLOCK;
	}
out:
	if(rc) erase->fail_addr=cursor;
	BMT_LEAVE(); return rc;
}
static int managed_isbad(struct mtd_info *mtd,loff_t from)
{
	u8 marker[2];
	int mapped,rc=BMT_ENTER();
	if(rc) return rc;
	rc=managed_ready(mtd); if(rc) goto out;
	if(from<0 || (u64)from>=mtd->size) { rc=-EINVAL; goto out; }
	mapped=map_block((u64)from/BMT_BLOCK);
	if(mapped<0) { rc=mapped; goto out; }
	rc=flash_markers(mtd,mapped,marker);
	if(!rc) rc=marker[0]!=255 || marker[1]!=255;
out:
	BMT_LEAVE(); return rc;
}
static int managed_markbad(struct mtd_info *mtd,loff_t from)
{
	int rc=BMT_ENTER();
	if(rc) return rc;
	rc=managed_ready(mtd);
	if(!rc) rc=managed_bounds(from,1,0,0,MTD_OPS_AUTO_OOB);
	/* A successful transparent remap is NOT logical retirement. UBI must
	 * enter read-only on this explicit refusal rather than corrupt accounting. */
	if(!rc) rc=-EOPNOTSUPP;
	BMT_LEAVE(); return rc;
}
