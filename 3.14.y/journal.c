/*
* HFSPlus journal implementation Tathagata Das 2010
*/

#define CONFIG_HFSPLUS_JOURNAL 1
#ifdef CONFIG_HFSPLUS_JOURNAL
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#include <asm/current.h>
#include <asm/unaligned.h>

#include "hfsplus_fs.h"
#include "hfsplus_raw.h"

#define HFS_SECTOR_SIZE_BITS	9      /* log_2(HFS_SECTOR_SIZE) */

#define sb_bread512(sb, sec, data) ({			\
	struct buffer_head *__bh;			\
	sector_t __block;				\
	loff_t __start;					\
	int __offset;					\
							\
	__start = (loff_t)(sec) << HFS_SECTOR_SIZE_BITS;\
	__block = __start >> (sb)->s_blocksize_bits;	\
	__offset = __start & ((sb)->s_blocksize - 1);	\
	__bh = sb_bread((sb), __block);			\
	if (likely(__bh != NULL))			\
		data = (void *)(__bh->b_data + __offset);\
	else						\
		data = NULL;				\
	__bh;						\
})

/* Calculate chesum of ptr of size len */
static int calc_checksum(unsigned char *ptr, int len)
{
	int i, chksum = 0;

	for (i=0; i<len; i++, ptr++)
		chksum = (chksum << 8) ^ (chksum + *ptr);

	return (~chksum);
}

static void swap_block_list_header(struct hfsplus_block_list_header *blhdr)
{
	int i;

	blhdr->num_blocks = swab16(blhdr->num_blocks);
	blhdr->bytes_used = swab32(blhdr->bytes_used);
	blhdr->checksum = swab32(blhdr->checksum);

	for (i=1; i<blhdr->num_blocks; i++) {
		blhdr->binfo[i].bnum = swab64(blhdr->binfo[i].bnum);
		blhdr->binfo[i].bsize = swab32(blhdr->binfo[i].bsize);
	}
}

static void swap_journal_header(struct hfsplus_journal_header *jh)
{
	jh->magic      = swab32(jh->magic);
	jh->endian     = swab32(jh->endian);
	jh->start      = swab64(jh->start);
	jh->end        = swab64(jh->end);
	jh->size       = swab64(jh->size);
	jh->blhdr_size = swab32(jh->blhdr_size);
	jh->checksum   = swab32(jh->checksum);
	jh->jhdr_size  = swab32(jh->jhdr_size);
}

void print_volume_header(struct super_block *sb)
{
	int i;
	unsigned char *vh_ptr = (unsigned char *)HFSPLUS_SB(sb)->s_vhdr;

	hfs_dbg(JOURNAL, "VOLUME HEADER\n");
	for (i=0; i<102; i++)
		hfs_dbg(JOURNAL, "%x ", vh_ptr[i]);
	hfs_dbg(JOURNAL, "\n");
}

static void print_journal_header(struct hfsplus_journal_header *jh)
{
	hfs_dbg(JOURNAL, "HFS+-fs: magic: %x\n endian: %x\n start: %llx\n end: %llx\n size: %llx\n blhdr_size: %x\n checksum: %x\n jhdr_size: %x\n", jh->magic, jh->endian, jh->start, jh->end, jh->size, jh->blhdr_size, jh->checksum, jh->jhdr_size);
}

static int map_journal_header(struct super_block *sb)
{
	struct hfsplus_journal *jnl = &(HFSPLUS_SB(sb)->jnl);
	u32 jh_block_number;

	jnl->jh_offset = be64_to_cpu(jnl->jibhdr->offset);
	jh_block_number = jnl->jh_offset >> sb->s_blocksize_bits;
	hfs_dbg(JOURNAL, "HFS+-fs: jh_block_number: %x\n", jh_block_number);
	jnl->jh_bh = sb_bread(sb, HFSPLUS_SB(sb)->blockoffset + jh_block_number);
	if (!jnl->jh_bh) {
		printk("HFS+-fs Line=%d: Error in buffer read\n", __LINE__);
		return HFSPLUS_JOURNAL_FAIL;
	}
	jnl->jhdr = (struct hfsplus_journal_header *)(jnl->jh_bh->b_data);

	return HFSPLUS_JOURNAL_SUCCESS;
}

/* Write journal header during replay */
static int hfsplus_replay_write_journal_header(struct super_block *sb)
{
	struct hfsplus_journal_header *jh = (struct hfsplus_journal_header *)(HFSPLUS_SB(sb)->jnl.jhdr);

	if (HFSPLUS_SB(sb)->jnl.flags == HFSPLUS_JOURNAL_SWAP) {
		swap_journal_header(jh);
		jh->checksum = 0;
		jh->checksum = swab32(calc_checksum((unsigned char *)jh, sizeof(struct hfsplus_journal_header)));
	}
	else {
		jh->checksum = 0;
		jh->checksum = calc_checksum((unsigned char *)jh, sizeof(struct hfsplus_journal_header));
	}

	/* Write it to disk */
	mark_buffer_dirty(HFSPLUS_SB(sb)->jnl.jh_bh);
	sync_dirty_buffer(HFSPLUS_SB(sb)->jnl.jh_bh);

	if (HFSPLUS_SB(sb)->jnl.flags == HFSPLUS_JOURNAL_SWAP)
		swap_journal_header(jh);

	return HFSPLUS_JOURNAL_SUCCESS;
}

static int hfsplus_write_journal_header(struct super_block *sb)
{
	struct hfsplus_journal_header *jh = (struct hfsplus_journal_header *)(HFSPLUS_SB(sb)->jnl.jhdr);

	jh->checksum = 0;
	jh->checksum = calc_checksum((unsigned char *)jh, sizeof(struct hfsplus_journal_header));

	/* Write it to disk */
	mark_buffer_dirty(HFSPLUS_SB(sb)->jnl.jh_bh);

	return HFSPLUS_JOURNAL_SUCCESS;
}

/* Create journal header, journal buffer and initialize them
 * Assume that presence of journal is already verified
*/
int hfsplus_journaled_create(struct super_block *sb)
{
	struct hfsplus_journal_header *jhdr;
	u64 jibsize = be64_to_cpu(HFSPLUS_SB(sb)->jnl.jibhdr->offset);

	hfs_dbg(JOURNAL, "sb->s_blocksize: %lx, jibsize: %llx\n", sb->s_blocksize, jibsize);

	/* Journal size is not aligned */
	if (((jibsize >> sb->s_blocksize_bits) << sb->s_blocksize_bits) != jibsize) {
		printk("HFS+-fs: journal size is not aligned\n");
		return HFSPLUS_JOURNAL_FAIL;
	}

	if (map_journal_header(sb) == HFSPLUS_JOURNAL_FAIL) {
		printk("HFS+-fs: Error in mapping journal header\n");
		return HFSPLUS_JOURNAL_FAIL;
	}

	jhdr = (struct hfsplus_journal_header *)HFSPLUS_SB(sb)->jnl.jhdr;

	/* Populate journal header and write it to the disk */
	jhdr->magic = HFSPLUS_JOURNAL_HEADER_MAGIC;
	jhdr->endian = HFSPLUS_JOURNAL_HEADER_ENDIAN;
	jhdr->start = sb->s_blocksize; /* First block is for journal header itself */
	jhdr->end = sb->s_blocksize; /* Initially journal buffer is empty */
	jhdr->size = jibsize;
	jhdr->blhdr_size = sb->s_blocksize;
	jhdr->jhdr_size = sb->s_blocksize; /* Assign first block for journal header */

	if (jhdr->start != jhdr->end) {
		printk("HFS+-fs: hfsplus_write_journal_header fail: Journal is not empty\n");
		return HFSPLUS_JOURNAL_FAIL;
	}

	return hfsplus_write_journal_header(sb);
}

/* Allocate block list header for a new transaction.
 * Assume that journal header is already initialized.
*/
static int hfsplus_journaled_write_transaction(struct super_block *sb, struct hfsplus_journal *jnl, struct page *page, void *vbuf, u64 sector_num, u32 bufsize)
{
	struct hfsplus_transaction *tr;
	u32 total_size = jnl->jhdr->blhdr_size + bufsize, tr_sector_number, *tr_buf, i;
	u64 tr_offset;
	struct buffer_head *tr_bh = NULL;

	/* Total size should be mulitple of sector size */
	if (((total_size >> HFSPLUS_SECTOR_SHIFT) << HFSPLUS_SECTOR_SHIFT) != total_size) {
      printk("HFS+-fs: total size is not aligned\n");
      return HFSPLUS_JOURNAL_FAIL;
   }

	tr = kmalloc(sizeof(struct hfsplus_transaction), GFP_KERNEL);
	if (tr == NULL) {
		printk("HFS+-fs: No memory of size %zu\n", sizeof(struct hfsplus_transaction));
		return HFSPLUS_JOURNAL_FAIL;
	}

	INIT_LIST_HEAD(&tr->list);

	/* Allocate memory for block list header, one block info and one data block of bufsize */
	tr->tbuf = kmalloc(total_size, GFP_KERNEL);
	if (tr->tbuf == NULL) {
		printk("HFS+-fs: No memory of size: %#x\n", total_size);
		goto tbuf_alloc_fail;
	}
	memset(tr->tbuf, 0, sizeof(struct hfsplus_block_list_header));
	/* Initialize the buffer (except block list header) with unimportant bytes */
	memset(tr->tbuf + sizeof(struct hfsplus_block_list_header), HFSPLUS_JOURNAL_UIBYTE, total_size - sizeof(struct hfsplus_block_list_header));

	/* Populate block list header */
	tr->blhdr = (struct hfsplus_block_list_header *)tr->tbuf;
	tr->blhdr->max_blocks = (jnl->jhdr->blhdr_size / sizeof(struct hfsplus_block_info)) - 1;
	tr->blhdr->num_blocks = 2;      /* One is for header and another is for the data */
	tr->blhdr->bytes_used = total_size;
	tr->blhdr->binfo[0].next = 0;

	/* Populate second block info */
	tr->binfo = (struct hfsplus_block_info *)(tr->tbuf + sizeof(struct hfsplus_block_list_header));
	tr->binfo->bnum = sector_num;
	tr->binfo->bsize = bufsize;
	tr->binfo->next = 0;

	if (HFSPLUS_SB(sb)->jnl.flags == HFSPLUS_JOURNAL_SWAP) {
		tr->binfo->bnum = swab64(tr->binfo->bnum);
		tr->binfo->bsize = swab32(tr->binfo->bsize);
		tr->blhdr->max_blocks = swab16(tr->blhdr->max_blocks);
		tr->blhdr->num_blocks = swab16(tr->blhdr->num_blocks);
		tr->blhdr->bytes_used = swab32(tr->blhdr->bytes_used);
		tr->blhdr->checksum = 0;
		tr->blhdr->checksum = swab32(calc_checksum((unsigned char *)tr->blhdr, sizeof(struct hfsplus_block_list_header)));
	}
	else {
		tr->blhdr->checksum = 0;
		tr->blhdr->checksum = calc_checksum((unsigned char *)tr->blhdr, sizeof(struct hfsplus_block_list_header));
	}

	/* Copy actual meta-data */
	if (page != NULL) {
		void *pbuf = kmap(page);
		if (pbuf) {
			memcpy(tr->tbuf + jnl->jhdr->blhdr_size, pbuf, bufsize);
			kunmap(pbuf);
		}
		else {
			printk("HFS+-fs Line=%d: Error in kmap\n", __LINE__);
			goto tr_bh_alloc_fail;
		}
	}
	else
		memcpy(tr->tbuf + jnl->jhdr->blhdr_size, (unsigned char *)vbuf, bufsize);

	/* Write transaction into the disk */
	tr_offset = jnl->jhdr->end + jnl->jh_offset;
	for (i=0; i < total_size / HFSPLUS_SECTOR_SIZE; i++) {
		tr_sector_number = tr_offset >> HFSPLUS_SECTOR_SHIFT;
		hfs_dbg(JTRANS, "tr_offset: %llx, tr_sector_number: %x\n", tr_offset, tr_sector_number);

		tr_bh = sb_bread512(sb, HFSPLUS_SB(sb)->blockoffset + tr_sector_number, tr_buf);
		if (tr_bh == NULL) {
			printk("HFS+-fs Line=%d: Error in read\n", __LINE__);
			goto tr_bh_alloc_fail;
		}

		memcpy(tr_buf, tr->tbuf + i*HFSPLUS_SECTOR_SIZE, HFSPLUS_SECTOR_SIZE);
		mark_buffer_dirty(tr_bh);
#if 0
		sync_dirty_buffer(tr_bh);
#endif

		/* Free buffer heads */
		brelse(tr_bh);

		tr_offset += HFSPLUS_SECTOR_SIZE;

		/* Check tr_offset reaches at the end of journal buffer */
		if (tr_offset == (jnl->jh_offset + jnl->jhdr->size)) {
			hfs_dbg(JTRANS, "tr_offset: %llx, jnl->jhdr->size: %llx, jh_offset: %llx\n", tr_offset, jnl->jhdr->size, jnl->jh_offset);
			tr_offset = jnl->jh_offset + jnl->jhdr->jhdr_size; /* Set to the beginning of the journal buffer */
		}
	}

	tr->journal_start = jnl->jhdr->start;
	tr->journal_end = tr_offset - jnl->jh_offset;
	tr->sequence_num = ++jnl->sequence_num;
	tr->num_blhdrs  = 1;
	tr->total_bytes = total_size;
	tr->jnl         = jnl;
	tr->tbuf_size = bufsize;
	tr->sector_number = sector_num;
	hfs_dbg(JTRANS, "end: %llx, start: %llx, sector_number: %llx\n", tr->journal_start, tr->journal_end, tr->sector_number);

	kfree(tr->tbuf);
	tr->tbuf = NULL;

	jnl->active_tr = tr;

	list_add_tail(&tr->list, &jnl->tr_list);

	return HFSPLUS_JOURNAL_SUCCESS;

tr_bh_alloc_fail:
	kfree(tr->tbuf);
	tr->tbuf = NULL;
tbuf_alloc_fail:
	list_del(&tr->list);
	kfree(tr);
	tr = NULL;
	return HFSPLUS_JOURNAL_FAIL;
}

/* Write a transaction into journal buffer before writing it to its original location.
*/
int hfsplus_journaled_start_transaction(struct page *page, struct super_block *sbp)
{
	struct inode *inode = NULL;
	struct super_block *sb = NULL;
	s32 block_num = -1, ret = HFSPLUS_JOURNAL_FAIL, bufsize = 0;
	u64 sector_num = 0, tr_size;
	u32 total_size;
	struct hfsplus_journal *jnl;

	hfs_dbg(JTRANS, "Entering into %s()\n", __FUNCTION__);

	if (sbp == NULL) {
		inode = page->mapping->host;
		sb = inode->i_sb;
	} else
		sb = sbp;

	jnl =	&HFSPLUS_SB(sb)->jnl;
	if (jnl->journaled != HFSPLUS_JOURNAL_PRESENT) {
		hfs_dbg(JTRANS, "%s: Not a journaled volume, return\n", __func__);
		return HFSPLUS_JOURNAL_SUCCESS;
	}

	down(&jnl->jnl_lock);

	/* Write one block into the journal log.
	 * Find out the correct transaction for this block and
	 * add that block into that block list header.
	*/
	if (sbp == NULL) {
		block_num = hfsplus_journaled_get_block(page);
		if (block_num == -1) {
			printk("HFS+-fs: Error in getting block for page index: %lx\n", page->index);
			up(&jnl->jnl_lock);
			return HFSPLUS_JOURNAL_FAIL;
		}

		/* Set sector number and buffer size*/
		hfs_dbg(JTRANS, "Need to write block number: %x to journal log\n", block_num);
		sector_num = (block_num * sb->s_blocksize) / HFSPLUS_SECTOR_SIZE;
		bufsize = PAGE_SIZE;
	} else {
	/* Must be Volume Header */
		sector_num = HFSPLUS_VOLHEAD_SECTOR;
		bufsize = HFSPLUS_SECTOR_SIZE;
	}

	hfs_dbg(JTRANS, "sector number: %llx, bufsize: %x\n", sector_num, bufsize);

	/* Check space in journal log for new transaction */
	total_size = jnl->jhdr->blhdr_size + bufsize;
	if (jnl->jhdr->end > jnl->jhdr->start)
		tr_size = jnl->jhdr->end - jnl->jhdr->start;
	else
		tr_size = jnl->jhdr->start - jnl->jhdr->end;

	if ((tr_size + (u64)total_size) > (jnl->jhdr->size - (u64)jnl->jhdr->jhdr_size)) {
		/* TODO: Free some memory from journal buffer */
		pr_err("Not enough free memory for writing this transaction\n");
		up(&jnl->jnl_lock);
		return HFSPLUS_JOURNAL_FAIL;
	}

	/* Prepare and write buffer for this transaction */
	if (sbp == NULL) {
		ret = hfsplus_journaled_write_transaction(sb, jnl, page, NULL, sector_num, bufsize);
	} else
		ret = hfsplus_journaled_write_transaction(sb, jnl, NULL, HFSPLUS_SB(sb)->s_vhdr, sector_num, bufsize);
	if (ret == HFSPLUS_JOURNAL_FAIL) {
		pr_err("HFS+-fs: Error in hfsplus_journaled_write_transaction\n");
		up(&jnl->jnl_lock);
		return ret;
	}

	jnl->jhdr->end = jnl->active_tr->journal_end;
	ret = hfsplus_write_journal_header(sb);

	hfs_dbg(JTRANS, "HFS+-fs: New transaction number: %d\n", jnl->sequence_num);

	up(&jnl->jnl_lock);
	return ret;
}

void hfsplus_journaled_end_transaction(struct page *page, struct super_block *sbp)
{
	struct inode *inode;
	struct super_block *sb;
	struct hfsplus_journal *jnl;
	struct list_head *liter = NULL, *tliter = NULL;

	hfs_dbg(JTRANS, "Entering into %s()\n", __FUNCTION__);

	if (sbp == NULL) {
		inode = page->mapping->host;
		sb = inode->i_sb;
	} else
		sb = sbp;

	jnl =	&HFSPLUS_SB(sb)->jnl;
	if (jnl->journaled != HFSPLUS_JOURNAL_PRESENT) {
		hfs_dbg(JOURNAL, "%s: Not a journaled volume, return\n", __func__);
		return;
	}

	down(&jnl->jnl_lock);

	/* FIXME: Remove the oldest transaction.
	 * Assuming that start and end transactions are called in same order of transaction.
	 */
	list_for_each_safe(liter, tliter, &jnl->tr_list) {
		struct hfsplus_transaction *tr = list_entry(liter, struct hfsplus_transaction, list);
		hfs_dbg(JTRANS, "start: %llx, end: %llx, sequence_num: %d, sector_num: %llx\n", tr->journal_start, tr->journal_end, tr->sequence_num, tr->sector_number);
		jnl->jhdr->start = tr->journal_end;
		hfsplus_write_journal_header(sb);
		list_del(&tr->list);
		kfree(tr);
		break;
	}

	up(&jnl->jnl_lock);

	return;
}

/* If the journal consists transaction then write them to disk.
 * Return success if it brings the file system into consistent state.
 * Otherwise return fail.
*/
static int hfsplus_journal_replay(struct super_block *sb)
{
	struct hfsplus_journal *jnl = &(HFSPLUS_SB(sb)->jnl);
	struct buffer_head *blhdr_bh = NULL, *tr_bh = NULL, *disk_bh = NULL;
	struct hfsplus_block_list_header *blhdr;
	u32 start_sector_number, tr_sector_number, disk_sector_number, i, ret = HFSPLUS_JOURNAL_FAIL;
	u64 tr_offset, disk_offset;
	struct hfsplus_journal_header *jh = (struct hfsplus_journal_header *)(HFSPLUS_SB(sb)->jnl.jhdr);
	unsigned char *tr_buf, *disk_buf;
	__be32 bufsize;

	if (jh->start == jh->end) {
		hfs_dbg(JREPLAY, "HFS+-fs: Journal is empty, nothing to replay\n");
		ret = hfsplus_replay_write_journal_header(sb);
		return ret;
	}

	if ((jh->start > jh->size) || (jh->end > jh->size)) {
		pr_err("HFS+-fs: Wrong start or end offset, start: %llx, end: %llx, jh_offset: %llx, size: %llx\n", jh->start, jh->end, jnl->jh_offset, jh->size);
		return ret;
	}

	if (jh->start == jh->size)
		jh->start = jh->jhdr_size;

	down(&jnl->jnl_lock);
	/* Go through each transaction */
	while (jh->start != jh->end) {
		if (blhdr_bh)
			brelse(blhdr_bh);

		start_sector_number = (jh->start + jnl->jh_offset) >> HFSPLUS_SECTOR_SHIFT;
		hfs_dbg(JREPLAY, "start: %llx, start_sector_number: %x\n", jh->start, start_sector_number);
		/* TODO: Wrap around */
		blhdr_bh = sb_bread512(sb, HFSPLUS_SB(sb)->blockoffset + start_sector_number, blhdr);
		if (!blhdr_bh) {
			printk("HFS+-fs Line=%d: Error in read\n", __LINE__);
			up(&jnl->jnl_lock);
			return ret;
		}

		if (jnl->flags == HFSPLUS_JOURNAL_SWAP)
			swap_block_list_header(blhdr);

		hfs_dbg(JREPLAY, "HFS+-fs: num_blocks: %x, bytes_used: %x\n", blhdr->num_blocks, blhdr->bytes_used);
		/* Point to the second block in the Volume, first block is already in block list header */
		tr_offset = jnl->jh_offset + jh->start + jh->blhdr_size;

		for (i=1; i<blhdr->num_blocks; i++) {
			bufsize = blhdr->binfo[i].bsize;
			disk_offset = blhdr->binfo[i].bnum << HFSPLUS_SECTOR_SHIFT;

			hfs_dbg(JREPLAY, "[i:%x] bnum: %llx, bsize: %x, bufsize: %x\n", i, blhdr->binfo[i].bnum, blhdr->binfo[i].bsize, bufsize);

			while (bufsize > 0) {
				/* Read one block */
				tr_sector_number = tr_offset >> HFSPLUS_SECTOR_SHIFT;
				hfs_dbg(JREPLAY, "[i:%x] tr_sector_number: %x, tr_offset: %llx\n", i, tr_sector_number, tr_offset);
				tr_bh = sb_bread512(sb, HFSPLUS_SB(sb)->blockoffset + tr_sector_number, tr_buf);
				if (!tr_bh) {
					printk("HFS+-fs Line=%d: Error in read\n", __LINE__);
					if (blhdr_bh)
						brelse(blhdr_bh);
					up(&jnl->jnl_lock);
					return ret;
				}

				disk_sector_number = disk_offset >> HFSPLUS_SECTOR_SHIFT;
				hfs_dbg(JREPLAY, "[i:%x] disk_sector_number: %x, disk_offset: %llx, bufsize: %x\n", i, disk_sector_number, disk_offset, bufsize);
				/* Read the same sector from the Volume */
				disk_bh = sb_bread512(sb, HFSPLUS_SB(sb)->blockoffset + disk_sector_number, disk_buf);
				if (!disk_bh) {
					printk("HFS+-fs Line=%d: Error in read\n", __LINE__);
					if (blhdr_bh)
						brelse(blhdr_bh);
					if (tr_bh)
						brelse(tr_bh);
					up(&jnl->jnl_lock);
					return ret;
				}

				/* Write transaction block to the disk block in sector wise */
				memcpy(disk_buf, tr_buf, HFSPLUS_SECTOR_SIZE);
				mark_buffer_dirty(disk_bh);
				sync_dirty_buffer(disk_bh);

				/* Free buffer heads */
				brelse(disk_bh);
				brelse(tr_bh);

				tr_offset += HFSPLUS_SECTOR_SIZE;
				disk_offset += HFSPLUS_SECTOR_SIZE;
				bufsize -= HFSPLUS_SECTOR_SIZE;

				/* Check tr_offset reaches at the end of journal buffer */
				if (tr_offset == (jnl->jh_offset + jh->size)) {
					printk("tr_offset: %llx, jh->size: %llx, jh_offset: %llx\n", tr_offset, jh->size, jnl->jh_offset);
					tr_offset = jnl->jh_offset + jh->jhdr_size; /* Set to the beginning of journal buffer */
				}
			}
		}

		/* Check position of start index, wrap around if necessary */
		if ((jh->start + blhdr->bytes_used) >= jh->size) {
			printk("start: %llx, jh->size: %llx, blhdr->bytes_used: %x\n", jh->start, jh->size, blhdr->bytes_used);
			jh->start = jh->jhdr_size + (jh->start + blhdr->bytes_used) - jh->size;
		} else
			jh->start += blhdr->bytes_used;
	}

	if (blhdr_bh)
		brelse(blhdr_bh);

	if (jh->start == jh->end) {
		ret = hfsplus_replay_write_journal_header(sb);
	} else {
		pr_err("HFS+-fs: %s Error in journal replay\n", __func__);
	}

	/* Populate Volume Header with new values */
	if (ret == HFSPLUS_JOURNAL_SUCCESS && HFSPLUS_SB(sb)->s_vhdr) {
		struct hfsplus_vh *vhdr = HFSPLUS_SB(sb)->s_vhdr;
		struct buffer_head *bh;

		hfs_dbg(JREPLAY, "Populate Volume Header again\n");
		HFSPLUS_SB(sb)->s_vhdr->attributes |= cpu_to_be32(HFSPLUS_VOL_UNMNT);

		bh = sb_bread512(sb, HFSPLUS_SB(sb)->blockoffset + HFSPLUS_VOLHEAD_SECTOR, vhdr);
		if (!bh) {
			pr_err("HFS+-fs Line=%d: Error in read\n", __LINE__);
			HFSPLUS_SB(sb)->s_vhdr = NULL;
			up(&jnl->jnl_lock);
			return HFSPLUS_JOURNAL_FAIL;
		}

		/* should still be the same... */
		if (be16_to_cpu(vhdr->signature) != HFSPLUS_VOLHEAD_SIG) {
			pr_err("Volume header signature (%x) is wrong\n", be16_to_cpu(vhdr->signature));
			brelse(bh);
			HFSPLUS_SB(sb)->s_vhdr = NULL;
			up(&jnl->jnl_lock);
			return HFSPLUS_JOURNAL_FAIL;
		}

		HFSPLUS_SB(sb)->s_vhdr = vhdr;
	}

	up(&jnl->jnl_lock);
	return ret;
}

/* Check consistency of journal log file in hfsplus volume
*/
int hfsplus_journaled_check(struct super_block *sb)
{
	struct hfsplus_journal_info_block *jib;
	struct hfsplus_journal_header *jh;
	u32 checksum, org_checksum;

	print_volume_header(sb);

	if (HFSPLUS_SB(sb)->jnl.journaled != HFSPLUS_JOURNAL_PRESENT) {
		printk("HFS+-fs: Journal is not present\n");
		return HFSPLUS_JOURNAL_CONSISTENT;
	}

	jib = (struct hfsplus_journal_info_block *)(HFSPLUS_SB(sb)->jnl.jibhdr);
	hfs_dbg(JOURNAL, "HFS+-fs: be32_to_cpu(jib->flags): %x\n", be32_to_cpu(jib->flags));

	/* Journal is on another volume, and the "on this volume" flag
	* isn't set
	*/
	if(be32_to_cpu(jib->flags) & HFSPLUS_JOURNAL_ON_OTHER_DEVICE &&
		!(be32_to_cpu(jib->flags) & HFSPLUS_JOURNAL_IN_FS)) {
		printk("HFS+-fs: Unable to access the journal.\n");
		return HFSPLUS_JOURNAL_INCONSISTENT;
	}

	/* Journal should be created in initialization.
	* Mark inconsistent if the journal is still not created yet
	*/
	if (be32_to_cpu(jib->flags) & HFSPLUS_JOURNAL_NEED_INIT) {
		printk("HFS+-fs: Error, journal is not created\n");
		return HFSPLUS_JOURNAL_INCONSISTENT;
	}

	hfs_dbg(JOURNAL, "HFS+-fs: Found Info Block and verified successfully.\n");
	jh = (struct hfsplus_journal_header *)(HFSPLUS_SB(sb)->jnl.jhdr);

	org_checksum = jh->checksum;
	jh->checksum = 0;

	if (jh->magic == swab32(HFSPLUS_JOURNAL_HEADER_MAGIC)) {
		org_checksum = swab32(org_checksum);
		checksum = calc_checksum((unsigned char *)jh, sizeof(struct hfsplus_journal_header));
		swap_journal_header(jh);
		HFSPLUS_SB(sb)->jnl.flags = HFSPLUS_JOURNAL_SWAP;
	}
	else
		checksum = calc_checksum((unsigned char *)jh, sizeof(struct hfsplus_journal_header));

	print_journal_header(jh);

	/* Verify the journal header */
	if(jh->magic != HFSPLUS_JOURNAL_HEADER_MAGIC || jh->endian != HFSPLUS_JOURNAL_HEADER_ENDIAN){
		printk("HFS+-fs: Journal header verification failed.\n");
		return HFSPLUS_JOURNAL_INCONSISTENT;
	}

	if (checksum != org_checksum) {
		jh->checksum = checksum;
		printk("HFS+-fs: Error in journal header checksum checksum: %x, org_checksum: %x\n", checksum, org_checksum);
		return HFSPLUS_JOURNAL_INCONSISTENT;
	}
	jh->checksum = checksum;

	hfs_dbg(JOURNAL, "HFS+-fs: No problem in magic number, endian and checksum\n");

	/* Compare start to end */
	if(jh->start == jh->end) {
		/* If they're the same, we can mount, it's clean */
		printk("HFS+-fs: Journal is empty means consistent\n");
		return HFSPLUS_JOURNAL_CONSISTENT;
	} else {
		/* Replay journal and bring the file system in consistent state */
		if (hfsplus_journal_replay(sb) == HFSPLUS_JOURNAL_FAIL) {
			/* Unable to replay */
			printk("HFS+-fs: Journal is non empty means inconsistent, please run fsck.hfsplus\n");
			return HFSPLUS_JOURNAL_INCONSISTENT;
		} else
			hfs_dbg(JOURNAL, "HFS+-fs: Journal replay done\n");
	}

	return HFSPLUS_JOURNAL_CONSISTENT;
}

/* Check journal present or not and initialize hfsplus_journal accordingly
 * Assume that super block and volume header are already initialized
*/
void hfsplus_journaled_init(struct super_block *sb, struct hfsplus_vh *vhdr)
{
	struct hfsplus_journal *jnl = &(HFSPLUS_SB(sb)->jnl);
	u32 jib_flags;

	jnl->journaled = !HFSPLUS_JOURNAL_PRESENT; /* Initialize as non-journaled */
	jnl->sbp = NULL;
	jnl->jh_bh = NULL;
	jnl->alloc_block = be32_to_cpu(vhdr->alloc_file.extents[0].start_block);
	jnl->ext_block = be32_to_cpu(vhdr->ext_file.extents[0].start_block);
	jnl->catalog_block = be32_to_cpu(vhdr->cat_file.extents[0].start_block);
	hfs_dbg(JOURNAL, "alloc_block: %x, ext_block: %x, catalog_block: %x\n", jnl->alloc_block, jnl->ext_block, jnl->catalog_block);

	if (vhdr->attributes & cpu_to_be32(HFSPLUS_VOL_JOURNALED)) {
		hfs_dbg(JOURNAL,"HFS+-fs: Journaled filesystem\n");
		jnl->jib_offset = be32_to_cpu(vhdr->journal_info_block);
		/* Check the journal info block to find the block # of the journal */
		jnl->jib_bh = sb_bread(sb, HFSPLUS_SB(sb)->blockoffset + jnl->jib_offset);
		if (!jnl->jib_bh) {
			printk("HFS+-fs Line=%d: Error in buffer read\n", __LINE__);
			return;
		}
		jnl->jibhdr = (struct hfsplus_journal_info_block *)(jnl->jib_bh->b_data);
		jib_flags = be32_to_cpu(jnl->jibhdr->flags);
		hfs_dbg(JOURNAL, "HFS+-fs: jib_flags: %x\n", jib_flags);
		if ((jib_flags & HFSPLUS_JOURNAL_ON_OTHER_DEVICE) && !(jib_flags & HFSPLUS_JOURNAL_IN_FS))
			goto init_fail;

		if (jib_flags & HFSPLUS_JOURNAL_NEED_INIT) {
			hfs_dbg(JOURNAL, "HFS+-fs: Journal is not created\n");
			if (hfsplus_journaled_create(sb) == 0) {
				HFSPLUS_SB(sb)->jnl.jibhdr->flags &= be32_to_cpu(~HFSPLUS_JOURNAL_NEED_INIT);
				/* write it to disk */
				mark_buffer_dirty(HFSPLUS_SB(sb)->jnl.jib_bh);
				sync_dirty_buffer(HFSPLUS_SB(sb)->jnl.jib_bh);
			} else {
				printk("HFS+-fs: Fail to create journal\n");
				goto init_fail;
			}
		}

		/* Check already initialize in journal create */
		if (jnl->jh_bh == NULL) {
			if (map_journal_header(sb) == HFSPLUS_JOURNAL_FAIL) {
				printk("HFS+-fs Line=%d: Error in buffer read\n", __LINE__);
				goto init_fail;
			}
		}

		jnl->sequence_num = 0;
		sema_init(&jnl->jnl_lock, 1);
		INIT_LIST_HEAD(&jnl->tr_list);
		jnl->sbp = sb;
		jnl->flags = !HFSPLUS_JOURNAL_SWAP;
		jnl->journaled = HFSPLUS_JOURNAL_PRESENT;
	}

	return;

init_fail:
	printk("HFS+-fs: Journal initialization fails\n");
	if (jnl->jib_bh)
		brelse(jnl->jib_bh);
}

/* Deinitialize journal if it is present */
void hfsplus_journaled_deinit(struct super_block *sb)
{
	if (HFSPLUS_SB(sb)->jnl.journaled != HFSPLUS_JOURNAL_PRESENT) {
		return;
	}

	hfsplus_journal_replay(sb);

	if (HFSPLUS_SB(sb)->jnl.jib_bh)
		brelse(HFSPLUS_SB(sb)->jnl.jib_bh);

	if (HFSPLUS_SB(sb)->jnl.jh_bh)
		brelse(HFSPLUS_SB(sb)->jnl.jh_bh);
}
#endif /* CONFIG_HFSPLUS_JOURNAL */
