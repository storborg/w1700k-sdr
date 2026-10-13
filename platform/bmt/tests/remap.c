/* SPDX-License-Identifier: GPL-2.0-only */
#define TRANSACTION_MODEL
#include "publication.c"
#include "airoha_bmt_transaction.h"

static struct airoha_bmt_transaction tx;
static unsigned char work[AIROHA_TRANSACTION_WORK_BYTES], payload[PART_BLOCK];
static unsigned char wanted[AIROHA_IMAGE_BYTES], previous[AIROHA_IMAGE_BYTES];
static int original_failure, stage_failure, original_erase_failure, preimage_error;
static int corrected_read, reentry;
static int fail_journal_clear;
static int permanent_original_erase;
static unsigned source_block, fail_page, data_calls, original_calls;
static struct airoha_bmt_change change;

static int data_read(void *ctx,unsigned b,unsigned p,unsigned char *main,unsigned char *oob)
{
	(void)ctx;
	if(b==source_block && preimage_error) return -EBADMSG;
	read_page(NULL,b,p,main);
	if(nand[b]) for(unsigned sec=0;sec<PART_SECTIONS;sec++) memcpy(oob+sec*14,nand[b]->spare[p]+sec*16+2,14);
	else memset(oob,255,PART_FREE);
	return corrected_read ? 3 : 0;
}
static void logical_image(unsigned b,unsigned char *out)
{
	for(unsigned p=0;p<PART_PAGES;p++) {
		assert(data_read(NULL,b,p,out+p*AIROHA_IMAGE_STRIDE,
		                out+p*AIROHA_IMAGE_STRIDE+PART_PAGE)>=0);
		out[p*AIROHA_IMAGE_STRIDE+PART_PAGE]=out[p*AIROHA_IMAGE_STRIDE+PART_PAGE+1]=255;
	}
}
static void durable_before_original(void)
{
	struct airoha_bmt_intent r;
	unsigned char digest[32];
	assert(nand[PART_SYS+2]);
	assert(!airoha_bmt_intent_decode(&r,nand[PART_SYS+2]->main[0],PART_PAGE,hash));
	image_hash(r.candidate_block,digest);
	assert(!memcmp(digest,r.data_digest,32));
}
static int data_program(void *ctx,unsigned b,unsigned p,const unsigned char *main,
		const unsigned char *oob,unsigned *written,unsigned *oobwritten)
{
	struct block *s=storage(b);
	int error=0;
	(void)ctx;
	assert(b==65 || b>=PART_SYS); assert(b!=PART_SYS && b!=PART_TOTAL-1 && b!=PART_SYS+2);
	if(b==source_block) { durable_before_original(); original_calls++; }
	if(reentry) {
		struct airoha_bmt_progress ignored;
		assert(airoha_bmt_transaction_apply(&tx,&change,&ignored)==-EBUSY);
	}
	before(); data_calls++;
	assert((int)p>=s->last && s->programs[p]<4);
	s->last=p; s->programs[p]++;
	if(original_failure && b==source_block && p==fail_page) { original_failure=0; error=1; }
	if(stage_failure && b!=source_block && p==fail_page) { stage_failure=0; error=1; }
	unsigned len=(torn() || error) ? PART_PAGE/2 : PART_PAGE;
	unsigned olen=(torn() || error) ? 7 : PART_FREE;
	for(unsigned i=0;i<len;i++) { assert((s->main[p][i]&main[i])==main[i]); s->main[p][i]&=main[i]; }
	for(unsigned i=0;i<olen;i++) {
		unsigned offset=(i/14)*16+2+i%14;
		assert((s->spare[p][offset]&oob[i])==oob[i]); s->spare[p][offset]&=oob[i];
	}
	if(len==PART_PAGE) s->spare[p][PART_SPARE-1]=0;
	/* Model a failed original program damaging a previously acknowledged page.
	 * The durable full-block after-image must preserve that page exactly. */
	if(error && b==source_block) s->main[0][0]&=0;
	*written=len; *oobwritten=olen;
	after();
	return error ? -EIO : 0;
}
static int data_erase(void *ctx,unsigned b)
{
	if(b==PART_SYS+2 && fail_journal_clear && tx.has_pending) { before(); return -EIO; }
	if(b==source_block && airoha_bmt_translate(&t,64)==(int)b) {
		assert(change.erase); original_calls++;
		/* Successful erases are intentionally direct. Only a program needs a
		 * durable after-image before touching its source. */
		if(nand[PART_SYS+2]) durable_before_original();
		if(original_erase_failure || permanent_original_erase) {
			original_erase_failure=0; before();
			for(unsigned p=0;p<PART_PAGES/2;p++) {
				memset(storage(b)->main[p],255,PART_PAGE);
				memset(storage(b)->spare[p],255,PART_SPARE);
			}
			after(); return -EIO;
		}
	}
	if(b==source_block && permanent_original_erase) { before(); return -EIO; }
	return erase(ctx,b);
}
static int meta_program(void *ctx,unsigned b,unsigned p,const unsigned char *main)
{
	/* A torn initial journal can stop within its protected header. */
	if(b==PART_SYS+2 && p==0 && actions+1==cut_action && cut_phase==2) {
		struct block *s=storage(b); before(); s->programs[0]++; s->last=0;
		for(unsigned i=0;i<64;i++) s->main[0][i]&=main[i];
		after();
	}
	return program_page(ctx,b,p,main);
}
static const struct airoha_bmt_data_io data_io={
	.metadata={.read_page=read_page,.program_page=meta_program,.erase=data_erase,
		.erased=erased,.markers=markers,.retire=retire,.hash=hash},
	.read_data=data_read,.program_data=data_program,
};

static int reload(void)
{
	unsigned selected=stock_table();
	assert(selected);
	t=original;
	assert(!airoha_bmt_parse_bmt(&t,storage(selected)->main[0],PART_PAGE));
	return airoha_bmt_transaction_init(&tx,&t,&data_io,64,BMT_WRITE_END,PART_SYS,selected,
		PART_SYS+2,work);
}
static void initial(int mapped,int erasing)
{
	/* Reuse the model's independent table fixtures, but start with no WAL or
	 * staged image. The transaction must create both itself. */
	setup(mapped,0);
	free(nand[PART_SYS+2]); nand[PART_SYS+2]=NULL; free(nand[PART_SYS+3]); nand[PART_SYS+3]=NULL;
	free(nand[65]); nand[65]=NULL;
	source_block=mapped ? PART_SYS+1 : 65;
	original_failure=stage_failure=original_erase_failure=preimage_error=0;
	corrected_read=reentry=fail_journal_clear=permanent_original_erase=0; data_calls=original_calls=0;
	struct block *s=storage(source_block);
	for(unsigned p=0;p<(erasing ? PART_PAGES : 1u);p++) {
		for(unsigned i=0;i<PART_PAGE;i++) s->main[p][i]=(i*3+p+19)%251;
		for(unsigned sec=0;sec<PART_SECTIONS;sec++) for(unsigned i=2;i<16;i++)
			s->spare[p][sec*16+i]=(sec==0 && i<4) ? 255 : (i*5+sec*7+p)%251;
		if(mapped) { s->spare[p][2]=65; s->spare[p][3]=0; }
		s->spare[p][PART_SPARE-1]=0; s->last=p; s->programs[p]=1;
	}
	for(unsigned i=0;i<sizeof payload;i++) payload[i]=(i*11+17)%251;
	change=(struct airoha_bmt_change){.logical=64,.offset=PART_PAGE,
		.length=erasing ? 0 : (PART_PAGES-1)*PART_PAGE,
		.data=erasing ? NULL : payload,.erase=erasing};
	logical_image(source_block,previous); memcpy(wanted,previous,sizeof wanted);
	if(erasing) memset(wanted,255,sizeof wanted);
	else for(unsigned i=0;i<change.length;i++)
		wanted[((i+PART_PAGE)/PART_PAGE)*AIROHA_IMAGE_STRIDE+(i%PART_PAGE)]=payload[i];
	actions=0; assert(!reload()); assert(!actions);
}
static void assert_result(int new_data)
{
	unsigned selected=stock_table(); struct airoha_bmt loaded=original;
	assert(selected && !airoha_bmt_parse_bmt(&loaded,storage(selected)->main[0],PART_PAGE));
	int physical=airoha_bmt_translate(&loaded,64); assert(physical>=0);
	logical_image(physical,image);
	assert(!memcmp(image,new_data ? wanted : previous,sizeof wanted));
}

static void basic(void)
{
	struct airoha_bmt_progress done;
	for(int mapped=0;mapped<2;mapped++) for(int erasing=0;erasing<2;erasing++) {
		initial(mapped,erasing); corrected_read=reentry=1;
		assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
		assert(done.data==change.length && !done.oob && !tx.has_pending && !tx.failed);
		assert_result(1);
		assert(!reload()); assert_result(1);
	}
	for(unsigned page=1;page<=PART_PAGES-1;page+=PART_PAGES/2-1) {
		initial(0,0); original_failure=1; fail_page=page;
		assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
		assert(done.data==change.length && t.bmt_size==1 && t.bmt_from[0]==65 && tx.remaps==1);
		assert_result(1); assert(!reload()); assert_result(1);
	}
	initial(1,0); original_failure=1; fail_page=32;
	assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
	assert(t.bmt_size==2 && t.bmt_from[0]==65 && t.bmt_to[0]!=PART_SYS+1);
	assert(t.bmt_from[1]==PART_SYS+1 && t.bmt_to[1]==PART_SYS+1); assert_result(1);
	initial(0,1); original_erase_failure=1;
	assert(!airoha_bmt_transaction_apply(&tx,&change,&done)); assert_result(1);
	for(int mapped=0;mapped<2;mapped++) {
		initial(mapped,1); permanent_original_erase=1;
		assert(!airoha_bmt_transaction_apply(&tx,&change,&done)); assert_result(1);
		assert(!reload()); assert_result(1);
		if(mapped) {
			/* Stock's allocator searches every destination, including ignored
			 * reserve sources; its reader still maps only the system key. */
			assert(t.bmt_size==2 && t.bmt_from[1]==PART_SYS+1 && t.bmt_to[1]==PART_SYS+1);
			assert(airoha_bmt_translate(&t,PART_SYS+1)==PART_SYS+1);
			assert(tx.pool[1]!=AIROHA_POOL_FREE);
		}
	}
	initial(0,0); stage_failure=1; fail_page=32;
	assert(!airoha_bmt_transaction_apply(&tx,&change,&done)); assert_result(1);
	assert(storage(PART_SYS+1)->spare[0][1]!=255);
	initial(0,0); preimage_error=1;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EBADMSG && !actions && !done.data);
	preimage_error=0; assert_result(0);
	initial(0,0); change.logical=63;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EROFS && !actions);
	initial(0,0); change.length=0; change.oob=payload; change.oob_length=1; change.oob_offset=PART_FREE;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EOPNOTSUPP && !actions);
	initial(0,0); change.offset=2*PART_PAGE+17; change.length=73;
	change.oob=payload+128; change.oob_offset=2*PART_FREE+2; change.oob_length=20;
	memcpy(wanted,previous,sizeof wanted);
	memcpy(wanted+2*AIROHA_IMAGE_STRIDE+17,payload,73);
	memcpy(wanted+2*AIROHA_IMAGE_STRIDE+PART_PAGE+2,payload+128,20);
	assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
	assert(done.data==73 && done.oob==20); assert_result(1);
	/* An erased earlier page below a used page requires relocation, not a
	 * forbidden backwards page program. */
	change.offset=PART_PAGE; change.length=PART_PAGE; change.oob_length=0;
	memcpy(wanted+AIROHA_IMAGE_STRIDE,payload,PART_PAGE);
	assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
	assert(tx.remaps==1); assert_result(1);
	initial(0,0); change.length=0; change.oob=payload;
	change.oob_offset=2*PART_FREE+PART_FREE-4; change.oob_length=8;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EOPNOTSUPP && !actions);
	initial(0,0); storage(PART_SYS+4)->main[0][0]=0x42;
	assert(!reload()); assert(tx.pool[4]==AIROHA_POOL_UNKNOWN);
	assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
	assert(storage(PART_SYS+4)->main[0][0]==0x42); assert_result(1);
	/* Three quarters of a page (1500 bytes on 2 KiB pages), so the torn half
	 * page below delivers part of it. */
	initial(0,0); change.offset=2*PART_PAGE+17; change.length=PART_PAGE*3/4-36;
	change.oob=payload+2048; change.oob_offset=2*PART_FREE+2; change.oob_length=20;
	memcpy(wanted,previous,sizeof wanted);
	memcpy(wanted+2*AIROHA_IMAGE_STRIDE+17,payload,change.length);
	memcpy(wanted+2*AIROHA_IMAGE_STRIDE+PART_PAGE+2,payload+2048,20);
	original_failure=1; fail_page=2; fail_erase=1;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EIO);
	/* The failed program tears page 2 at half a page and 7 OOB bytes. */
	assert(done.data==PART_PAGE/2-17 && done.oob==5 && tx.failed && tx.has_pending);
	unsigned prior_actions=actions;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EROFS && actions==prior_actions);
	fail_erase=0; assert(!reload()); assert_result(1);
	initial(0,0); fail_journal_clear=1;
	assert(airoha_bmt_transaction_apply(&tx,&change,&done)==-EIO && tx.failed && tx.has_pending);
	assert_result(1); fail_journal_clear=0; assert(!reload()); assert_result(1);
	initial(0,0);
	assert(airoha_bmt_transaction_init(&tx,&t,&data_io,64,BMT_WRITE_END,PART_SYS,PART_TOTAL-1,
		PART_SYS+2,NULL)==-ENOMEM);
	assert(!actions);
	storage(PART_SYS+2)->spare[0][0]=0;
	assert(reload()==-EIO && !actions);
	puts("full data/OOB preservation, first/middle/last failures, repeated wear, erase/stage failure and reentry: passed");
}

static void transaction_cut(void)
{
	struct airoha_bmt_progress done;
	if(!setjmp(reset_point)) { airoha_bmt_transaction_apply(&tx,&change,&done); assert(!"cut not reached"); }
}
static void resets(void)
{
	unsigned cuts=0, refusals=0, completed=0, aborted=0;
	for(int erasing=0;erasing<2;erasing++) for(int failed=0;failed<2;failed++) {
		/* Ordinary erase deliberately has no NAND WAL before the controller
		 * operation. Its interrupted states are idempotent-retry cases below. */
		if(erasing) continue;
		struct airoha_bmt_progress done;
		initial(0,erasing); original_failure=failed&&!erasing;
		original_erase_failure=failed&&erasing; fail_page=32;
		assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
		unsigned total=actions;
		for(unsigned cut=1;cut<=total;cut++) for(unsigned phase=0;phase<3;phase++) {
			initial(0,erasing); original_failure=failed&&!erasing;
			original_erase_failure=failed&&erasing; fail_page=32;
			cut_action=cut; cut_phase=phase; transaction_cut(); cut_action=0;
			original_failure=original_erase_failure=0;
			int rc=reload();
			if(rc) {
				/* Known damaged WAL: stop explicitly. These cuts occur before
				 * original I/O or during final WAL cleanup, so acknowledged
				 * bytes remain physically readable through the read-only map. */
				assert(rc==-EINVAL || rc==-EBADMSG || rc==-EIO || rc==-EUCLEAN);
				refusals++;
			}
			unsigned selected=stock_table(); struct airoha_bmt loaded=original;
			assert(!airoha_bmt_parse_bmt(&loaded,storage(selected)->main[0],PART_PAGE));
			logical_image(airoha_bmt_translate(&loaded,64),image);
			if(!memcmp(image,wanted,sizeof wanted)) completed++;
			else { assert(!memcmp(image,previous,sizeof previous)); aborted++; }
			cuts++;
		}
	}
	for(int failed=0;failed<2;failed++) for(unsigned phase=0;phase<3;phase++) {
		struct airoha_bmt_progress done;
		initial(0,1);original_erase_failure=failed;
		cut_action=1;cut_phase=phase;transaction_cut();cut_action=0;
		original_erase_failure=0;
		assert(!reload());
		assert(!airoha_bmt_transaction_apply(&tx,&change,&done));
		assert_result(1);cuts++;completed++;
	}
	printf("complete transaction NAND cuts: %u; new=%u old=%u explicit damaged-WAL refusals=%u\n",cuts,completed,aborted,refusals);
}
int main(void)
{
	basic(); resets();
	for(unsigned b=0;b<PART_TOTAL;b++) free(nand[b]);
	return 0;
}
