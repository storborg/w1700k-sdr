/* SPDX-License-Identifier: GPL-2.0-only */
/* Synthetic physical NAND callbacks; test the actual compiled bindings. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int fail_alloc;
#include LAYER_FILE
#ifdef TEST_LINUX
#define attach sdr_bmt_attach
#define detach sdr_bmt_detach
#else
#define attach airoha_bmt_attach
#define detach airoha_bmt_detach
#endif
#include "part.h"
#define BS PART_BLOCK
#define PS PART_PAGE
#define OS PART_SPARE
#define LAST (PART_TOTAL-1)
static struct mtd_info m;
static int scanning, missing, corrupt, stale, marker_error, short_scan, top_bad;
static int fault, partial, calls, mutation_calls, bad_queries;
static unsigned pool=PART_POOL, SYS=PART_SYS;
static unsigned char data[3*BS], oob[3*BS], expected_data[3*BS], expected_oob[3*BS];
static unsigned char bbt[PS], new_bbt[PS], old_bmt[PS], new_bmt[PS];
static void put16(unsigned char *p, unsigned v) { p[0]=v; p[1]=v>>8; }
/* Block 5 is factory bad (OOB byte 0), and with top_bad also one block in the
 * span stock's pool scan reads. A retired table carries the worn marker. */
static int factory_marked(unsigned b) { return b==5 || (top_bad && b==LAST-1); }
static int worn_marked(unsigned b)
{ return ((stale&1) && b==LAST) || ((stale&2) && b==PART_SYS); }
static void tables(void)
{
 unsigned sum=2;
 memset(bbt,255,sizeof bbt); memcpy(bbt,"RAWB",4); bbt[8]=1; bbt[9]=1;
 put16(bbt+12,5);
 for(unsigned i=12;i<512;i++) sum+=bbt[i];
 bbt[4]=sum; bbt[5]=sum>>8; bbt[6]=bbt[7]=0;
 memcpy(new_bbt,bbt,sizeof new_bbt);put16(new_bbt+12,6);
 sum++;new_bbt[4]=sum;new_bbt[5]=sum>>8;
 memset(old_bmt,255,sizeof old_bmt); memcpy(old_bmt,"BMT",3);
 old_bmt[3]=1; old_bmt[5]=1; put16(old_bmt+20,7); put16(old_bmt+22,SYS+4);
 sum=2; for(unsigned i=20;i<20+4*pool;i++) sum+=old_bmt[i]; old_bmt[6]=sum;
 memcpy(new_bmt,old_bmt,sizeof new_bmt); put16(new_bmt+22,SYS+5);
 sum=2; for(unsigned i=20;i<20+4*pool;i++) sum+=new_bmt[i]; new_bmt[6]=sum;
}
static unsigned physical(unsigned logical)
{
 unsigned p=logical+(logical>=5 && logical<SYS-1);
 return p==7 ? SYS+4 : p;
}
static unsigned char tag(unsigned page, unsigned column)
{ return (page*13+page/64+column*7)%251; }
static int driver_io(struct mtd_info *dev,loff_t addr,struct mtd_oob_ops *ops,int write)
{
 unsigned per=ops->mode==MTD_OPS_AUTO_OOB ? dev->oobavail : OS;
 size_t dl=ops->len, ol=ops->ooblen;
 calls++; if(write) mutation_calls++;
 if(!write && !ops->len && ops->mode==MTD_OPS_RAW &&
    (ops->ooblen==1 || ops->ooblen==2) && !ops->ooboffs && !(addr%BS)) {
   bad_queries++;
   if(marker_error) return -EIO;
   ops->oobbuf[0]=factory_marked(addr/BS) ? 0 : 255;
   if(ops->ooblen==2) ops->oobbuf[1]=worn_marked(addr/BS) ? 0 : 255;
   ops->oobretlen=ops->ooblen;return 0;
 }
 if(scanning) {
   assert(!write); memset(ops->datbuf,255,ops->len);
   if(!missing && addr/BS==PART_SYS) memcpy(ops->datbuf,bbt,ops->len);
   if(!missing && addr/BS==LAST) {
     memcpy(ops->datbuf,old_bmt,ops->len); if(corrupt) ops->datbuf[6]^=1;
   }
   if((stale&1) && addr/BS==LAST-2) memcpy(ops->datbuf,new_bmt,ops->len);
   if((stale&2) && addr/BS==PART_SYS+1) memcpy(ops->datbuf,new_bbt,ops->len);
   ops->retlen=short_scan ? 0 : ops->len; return 0;
 }
 if(partial>=0) { if(dl>(size_t)partial) dl=partial; if(ol>(size_t)partial) ol=partial; }
 for(size_t i=0;i<dl;i++) {
   unsigned char v=tag((addr+i)/PS,(addr+i)%PS);
   if(write) assert(ops->datbuf[i]==v); else ops->datbuf[i]=v;
 }
 for(size_t i=0;i<ol;i++) {
   unsigned col=i+ops->ooboffs;
   unsigned char v=tag(addr/PS+col/per,PS+col%per);
   if(write) assert(ops->oobbuf[i]==v); else ops->oobbuf[i]=v;
 }
 ops->retlen=dl; ops->oobretlen=ol; return fault;
}
static int driver_read(struct mtd_info *d,loff_t a,struct mtd_oob_ops *o) { return driver_io(d,a,o,0); }
static int driver_write(struct mtd_info *d,loff_t a,struct mtd_oob_ops *o) { return driver_io(d,a,o,1); }
static int driver_erase(struct mtd_info *d,struct erase_info *e) { (void)d;(void)e; mutation_calls++;return 0; }
static int driver_bad(struct mtd_info *d,loff_t a)
{ (void)d;bad_queries++; if(marker_error) return -EIO; return factory_marked(a/BS) || worn_marked(a/BS); }
static int driver_mark(struct mtd_info *d,loff_t a) { (void)d;(void)a;mutation_calls++;return 0; }
static void init_mtd(struct mtd_info *d)
{
 memset(d,0,sizeof *d); d->size=(unsigned long long)PART_TOTAL*BS; d->erasesize=BS;d->writesize=PS;
 d->oobsize=OS;d->oobavail=32;d->flags=MTD_WRITEABLE;
 d->_read_oob=driver_read;d->_write_oob=driver_write;d->_erase=driver_erase;
 d->_block_isbad=driver_bad;d->_block_markbad=driver_mark;
}
static void reset(void)
{
 detach(&m);init_mtd(&m); scanning=1;missing=corrupt=stale=marker_error=short_scan=top_bad=0;
 pool=PART_POOL;SYS=PART_SYS;
 fault=calls=mutation_calls=bad_queries=fail_alloc=0;partial=-1;tables();
}
static void open_mtd(void) { assert(attach(&m)==0);assert(mutation_calls==0);scanning=0;calls=0; }
static void transfers(void)
{
 unsigned cases=0;
 reset();open_mtd();
 for(unsigned mode=0;mode<3;mode++) for(unsigned logical=4;logical<=6;logical++)
 for(unsigned start=0;start<3;start++) for(unsigned kind=0;kind<5;kind++) {
   unsigned per=mode==MTD_OPS_AUTO_OOB ? 32 : OS;
   loff_t addr=(loff_t)logical*BS+BS-PS*(start+1)+17;
   size_t len=kind==0 ? 0 : (kind==3 ? 23 : BS+PS*2);
   size_t olen=kind==1 ? 0 : (kind==4 ? 9 : per*(PART_PAGES+4)-11);
   unsigned off=11;
   for(size_t i=0;i<len;i++) {
     loff_t a=addr+i;expected_data[i]=tag((physical(a/BS)*BS+a%BS)/PS,a%PS);
   }
   for(size_t i=0;i<olen;i++) {
     unsigned page=addr/PS+(i+off)/per;
     expected_oob[i]=tag(physical(page/PART_PAGES)*PART_PAGES+page%PART_PAGES,PS+(i+off)%per);
   }
   for(int write=0;write<2;write++) {
     struct mtd_oob_ops op={.mode=mode,.len=len,.ooblen=olen,.ooboffs=off,
       .datbuf=len ? data : NULL,.oobbuf=olen ? oob : NULL};
     memset(data,0,sizeof data);memset(oob,0,sizeof oob);
     if(write) { memcpy(data,expected_data,len);memcpy(oob,expected_oob,olen); }
     int ret=(write ? m._write_oob : m._read_oob)(&m,addr,&op);
     assert(ret==0 && op.retlen==len && op.oobretlen==olen);
     assert(!memcmp(data,expected_data,len));assert(!memcmp(oob,expected_oob,olen));cases++;
   }
 }
 printf("translated data/OOB cases: %u\n",cases);
}
static void failures(void)
{
 for(unsigned i=0;i<6;i++) {
   reset();switch(i) {
   case 0:missing=1;break;case 1:corrupt=1;break;case 2:marker_error=1;break;
   case 3:short_scan=1;break;case 4:fail_alloc=1;break;case 5:m.size=BS*100;break;
   }
   assert(attach(&m)<0);assert(!layer.mtd);assert(mutation_calls==0);
   missing=corrupt=marker_error=short_scan=fail_alloc=0;init_mtd(&m);open_mtd();
 }
 for(unsigned retired=1;retired<=3;retired++) {
   reset();stale=retired;open_mtd();assert(bad_queries>0);
   assert(layer.t.bbt_entries[0]==((retired&2) ? 6 : 5));
   assert(airoha_bmt_translate(&layer.t,6)==(int)SYS+((retired&1) ? 5 : 4));
   /* A worn marker never moves stock's pool. */
   assert(layer.t.system_blocks==PART_SYS);
 }
 /* A factory-bad block among the top blocks moves the reserve down by one
  * where the pool is not clamped; the tables then validate at that extent. */
 reset();top_bad=1;
 if(PART_POOL<250) { pool=PART_POOL+1; SYS=PART_SYS-1; tables(); }
 open_mtd();
 assert(layer.t.system_blocks==PART_TOTAL-pool && layer.t.system_blocks==SYS);
 assert(airoha_bmt_translate(&layer.t,6)==(int)SYS+4);
 if(PART_POOL<250) {
   /* Tables checksummed for the unmoved pool are refused, never repaired. */
   reset();top_bad=1;assert(attach(&m)<0 && !layer.mtd && !mutation_calls);
 }
 reset();open_mtd();
 struct mtd_info other;init_mtd(&other);assert(attach(&other)==-ENOSPC);
 detach(&other);assert(layer.mtd==&m);
 detach(&m);assert(m._read_oob==driver_read);assert(!layer.mtd);
 scanning=1;assert(attach(&other)==0);detach(&other);
 reset();m.flags=0;m._write_oob=NULL;m._erase=NULL;m._block_markbad=NULL;
 open_mtd();assert(!m._write_oob && !m._erase && !m._block_markbad);
 puts("attachment errors, retired table, detach/rebind, read-only callbacks: passed");
}
static void counts(void)
{
 const int errors[]={-EBADMSG,-EUCLEAN,3,-EIO,0};
 for(unsigned i=0;i<sizeof errors/sizeof *errors;i++) {
   reset();open_mtd();fault=errors[i];
   struct mtd_oob_ops op={.len=PS,.datbuf=data,.ooblen=OS,.oobbuf=oob};
   int ret=m._read_oob(&m,0,&op);
   assert(ret==fault && op.retlen==PS && op.oobretlen==OS);
 }
 reset();open_mtd();fault=-EIO;partial=PS;
 struct mtd_oob_ops op={.len=2*PS,.datbuf=data,.ooblen=2*OS,.oobbuf=oob};
 for(unsigned i=0;i<PS;i++) data[i]=tag(i/PS,i%PS);
 for(unsigned i=0;i<2*OS;i++) oob[i]=tag(i/OS,PS+i%OS);
 assert(m._write_oob(&m,0,&op)==-EIO && op.retlen==PS && op.oobretlen==2*OS);
 /* Simulate MEMREAD's accepted-ECC status and remaining-byte advancement. */
 reset();open_mtd();fault=-EBADMSG;partial=PS;
 size_t remaining=PS*5,done=0;unsigned iterations=0;
 while(remaining) {
   op=(struct mtd_oob_ops){.len=remaining,.datbuf=data};
   assert(m._read_oob(&m,done,&op)==-EBADMSG);
   assert(op.retlen==PS);done+=op.retlen;remaining-=op.retlen;assert(++iterations<=5);
 }
 partial=0;op=(struct mtd_oob_ops){.len=PS,.datbuf=data};
 assert(m._read_oob(&m,0,&op)==-EIO && op.retlen==0);
 reset();open_mtd();fault=-EBADMSG;
 op=(struct mtd_oob_ops){.len=2*PS,.datbuf=data,.ooblen=2*OS,.oobbuf=oob};
 assert(m._read_oob(&m,5*BS-PS,&op)==-EBADMSG);
 assert(op.retlen==2*PS && op.oobretlen==2*OS && calls==2);
 puts("ECC delivery, partial writes, MEMREAD progress and zero-progress refusal: passed");
}
#ifdef TEST_LINUX
#include "lifecycle.inc"
#include "memread.inc"
#endif
int main(void)
{
 transfers();failures();counts();detach(&m);
#ifdef TEST_LINUX
 lifecycle();memread();
#endif
 return 0;
}
