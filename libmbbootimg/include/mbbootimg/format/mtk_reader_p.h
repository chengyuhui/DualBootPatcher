/*
 * Copyright (C) 2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "mbbootimg/guard_p.h"

#include "mbbootimg/format/android_p.h"
#include "mbbootimg/format/mtk_p.h"
#include "mbbootimg/reader.h"

#define MTK_READER_MAX_ENTRIES          10

#define MTK_READER_ENTRY_BEGIN          (-1)
#define MTK_READER_ENTRY_END            (-2)


MB_BEGIN_C_DECLS

struct MtkReaderEntry
{
    int type;
    uint64_t offset;
    uint32_t size;
};

struct MtkReaderCtx
{
    // Header values
    AndroidHeader hdr;
    MtkHeader mtk_kernel_hdr;
    MtkHeader mtk_ramdisk_hdr;

    // Offsets
    bool have_header_offset;
    uint64_t header_offset;
    bool have_mtkhdr_offsets;
    uint64_t mtk_kernel_offset;
    uint64_t mtk_ramdisk_offset;

    uint64_t file_size;

    MtkReaderEntry entries[MTK_READER_MAX_ENTRIES];
    size_t entries_len;
    MtkReaderEntry *entry;

    // For reading
    uint64_t read_start_offset;
    uint64_t read_end_offset;
    uint64_t read_cur_offset;
};

struct MtkReaderEntry * mtk_reader_next_entry(struct MtkReaderCtx *ctx);
//int find_android_header(struct MbBiReader *bir, struct MbFile *file,
//                        uint64_t max_header_offset,
//                        struct AndroidHeader *header_out, uint64_t *offset_out);
//int find_samsung_seandroid_magic(struct MbBiReader *bir, struct MbFile *file,
//                                 struct AndroidHeader *hdr,
//                                 uint64_t *offset_out);
//int android_set_header(struct AndroidHeader *hdr, struct MbBiHeader *header);

int mtk_reader_bid(MbBiReader *bir, void *userdata, int best_bid);
int mtk_reader_set_option(MbBiReader *bir, void *userdata,
                          const char *key, const char *value);
int mtk_reader_read_header(MbBiReader *bir, void *userdata,
                           MbBiHeader *header);
int mtk_reader_read_entry(MbBiReader *bir, void *userdata,
                          MbBiEntry *entry);
int mtk_reader_read_data(MbBiReader *bir, void *userdata,
                         void *buf, size_t buf_size,
                         size_t *bytes_read);
int mtk_reader_free(MbBiReader *bir, void *userdata);

MB_END_C_DECLS
