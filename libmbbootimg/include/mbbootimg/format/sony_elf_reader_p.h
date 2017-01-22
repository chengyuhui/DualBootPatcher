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

#include "mbbootimg/format/sony_elf_p.h"
#include "mbbootimg/reader.h"

#define SONY_ELF_READER_MAX_ENTRIES     10

#define SONY_ELF_READER_ENTRY_BEGIN     (-1)
#define SONY_ELF_READER_ENTRY_END       (-2)


MB_BEGIN_C_DECLS

struct SonyElfReaderEntry
{
    int type;
    uint64_t offset;
    uint32_t size;
};

struct SonyElfReaderCtx
{
    // Header values
    Sony_Elf32_Ehdr hdr;

    bool have_header;

    uint64_t file_size;

    SonyElfReaderEntry entries[SONY_ELF_READER_MAX_ENTRIES];
    size_t entries_len;
    SonyElfReaderEntry *entry;

    // For reading
    uint64_t read_start_offset;
    uint64_t read_end_offset;
    uint64_t read_cur_offset;
};

struct SonyElfReaderEntry * sony_elf_reader_next_entry(struct SonyElfReaderCtx *ctx);
int find_sony_elf_header(MbBiReader *bir, MbFile *file,
                         Sony_Elf32_Ehdr *header_out);

int sony_elf_reader_bid(MbBiReader *bir, void *userdata, int best_bid);
int sony_elf_reader_read_header(MbBiReader *bir, void *userdata,
                                MbBiHeader *header);
int sony_elf_reader_read_entry(MbBiReader *bir, void *userdata,
                               MbBiEntry *entry);
int sony_elf_reader_read_data(MbBiReader *bir, void *userdata,
                              void *buf, size_t buf_size,
                              size_t *bytes_read);
int sony_elf_reader_free(MbBiReader *bir, void *userdata);

MB_END_C_DECLS
