/* SPDX-License-Identifier: GPL-2.0-only */
static void ubi_consumers(void)
{
 struct ubi_device ubi={.mtd=&m,.peb_count=3504,.peb_size=BS,
  .hdrs_min_io_size=PS,.leb_start=2*PS,.bad_allowed=1,
  .beb_rsvd_pebs=3,.avail_pebs=10,.good_peb_count=3504};
 base(0);memset(data,0x67,PS);fail_original=1;
 write_calls=erase_calls=markbad_calls=0;
 assert(!ubi_io_write(&ubi,data,0,0,PS) && write_calls==1 && last_written==PS);
 assert(layer.writer->remaps==1 && !markbad_calls);
 assert(!do_sync_erase(&ubi,0) && erase_calls==1);
 assert(ubi_io_mark_bad(&ubi,0)==-EOPNOTSUPP);
 assert(actual_bad_peb_tail(&ubi,0)==-EOPNOTSUPP && ubi.ro_mode);
 assert(ubi.beb_rsvd_pebs==3 && !ubi.bad_peb_count);
 ubi.ro_mode=0;ubi.beb_rsvd_pebs=0;
 assert(actual_bad_peb_tail(&ubi,0)==-EOPNOTSUPP && ubi.ro_mode && ubi.avail_pebs==10);
 base(0);ubi.ro_mode=0;fail_original=fail_metadata=1;
 assert(ubi_io_write(&ubi,data,0,0,PS)==-EIO && last_written==PS/2);
 unsigned before=mutations;erase_calls=0;
 assert(do_sync_erase(&ubi,0)==-EIO && erase_calls==UBI_IO_RETRIES+1);
 assert(mutations==before && actual_bad_peb_tail(&ubi,0)==-EIO && ubi.ro_mode);
 assert(ubi_io_write(&ubi,data,0,0,PS)==-EROFS);
 puts("actual UBI consumers: remap success, partial failure, bounded erase retries and markbad refusal to read-only passed");
}
