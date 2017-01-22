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
#include "mbbootimg/reader.h"

#define ANDROID_READER_MAX_ENTRIES      10

#define ANDROID_READER_ENTRY_BEGIN      (-1)
#define ANDROID_READER_ENTRY_END        (-2)


MB_BEGIN_C_DECLS

struct AndroidReaderEntry
{
    int type;
    uint64_t offset;
    uint32_t size;
};

struct AndroidReaderCtx
{
    // Header values
    AndroidHeader hdr;

    // Offsets
    bool have_header_offset;
    uint64_t header_offset;
    bool have_samsung_offset;
    uint64_t samsung_offset;

    uint64_t file_size;

    AndroidReaderEntry entries[ANDROID_READER_MAX_ENTRIES];
    size_t entries_len;
    AndroidReaderEntry *entry;

    bool allow_truncated_dt;

    // For reading
    uint64_t read_start_offset;
    uint64_t read_end_offset;
    uint64_t read_cur_offset;
};

struct AndroidReaderEntry * android_reader_next_entry(struct AndroidReaderCtx *ctx);
int find_android_header(struct MbBiReader *bir, struct MbFile *file,
                        uint64_t max_header_offset,
                        struct AndroidHeader *header_out, uint64_t *offset_out);
int find_samsung_seandroid_magic(struct MbBiReader *bir, struct MbFile *file,
                                 struct AndroidHeader *hdr,
                                 uint64_t *offset_out);
int android_set_header(struct AndroidHeader *hdr, struct MbBiHeader *header);

int android_reader_bid(MbBiReader *bir, void *userdata, int best_bid);
int android_reader_set_option(MbBiReader *bir, void *userdata,
                              const char *key, const char *value);
int android_reader_read_header(MbBiReader *bir, void *userdata,
                               MbBiHeader *header);
int android_reader_read_entry(MbBiReader *bir, void *userdata,
                              MbBiEntry *entry);
int android_reader_read_data(MbBiReader *bir, void *userdata,
                             void *buf, size_t buf_size,
                             size_t *bytes_read);
int android_reader_free(MbBiReader *bir, void *userdata);

MB_END_C_DECLS
