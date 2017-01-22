/*
 * Copyright (C) 2015-2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
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

#include "mbbootimg/format/mtk_writer_p.h"

#include <algorithm>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>

#include <openssl/sha.h>

#include "mbcommon/endian.h"
#include "mbcommon/file.h"
#include "mbcommon/file_util.h"
#include "mbcommon/string.h"

#include "mbbootimg/entry.h"
#include "mbbootimg/header.h"
#include "mbbootimg/writer.h"
#include "mbbootimg/writer_p.h"


MB_BEGIN_C_DECLS

void mtk_writer_advance_state(MtkWriterCtx *const ctx)
{
    if (ctx->entry->type != MTK_WRITER_ENTRY_END) {
        ++ctx->entry;
    }
}

void mtk_writer_update_size_if_unset(MtkWriterCtx *ctx, uint32_t size)
{
    if (!ctx->entry->size_set) {
        ctx->entry->size = size;
        ctx->entry->size_set = true;
    }
}

static int mtk_check_header_size(MbBiWriter *biw, MtkWriterEntry *entry)
{
    switch (entry->type) {
    case MB_BI_ENTRY_MTK_KERNEL_HEADER:
    case MB_BI_ENTRY_MTK_RAMDISK_HEADER:
        if (entry->size != sizeof(MtkHeader)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "MTK header entry has invalid size: %"
                                   MB_PRIzu, sizeof(MtkHeader));
            return MB_BI_FAILED;
        }
        break;
    }

    return MB_BI_OK;
}

static int mtk_writer_add_entry(MbBiWriter *biw, MtkWriterCtx *ctx,
                                int type, uint32_t size, bool size_set,
                                bool align)
{
    if (ctx->entries_len == sizeof(ctx->entries) / sizeof(ctx->entries[0])) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Too many entries");
        return MB_BI_FATAL;
    }

    MtkWriterEntry *entry = &ctx->entries[ctx->entries_len];
    entry->type = type;
    entry->offset = 0;
    entry->size = size;
    entry->size_set = size_set;
    entry->align = align;

    ++ctx->entries_len;

    return MB_BI_OK;
}

static int _mtk_header_update_size(MbBiWriter *biw, MbFile *file,
                                   uint64_t offset, uint32_t size)
{
    uint32_t le32_size = mb_htole32(size);
    size_t n;
    int ret;

    if (offset > SIZE_MAX - offsetof(MtkHeader, size)) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "MTK header offset too large");
        return MB_BI_FATAL;
    }

    ret = mb_file_seek(biw->file, offset + offsetof(MtkHeader, size),
                       SEEK_SET, nullptr);
    if (ret != MB_FILE_OK) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to seek to MTK size field: %s",
                               mb_file_error_string(biw->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    }

    ret = mb_file_write_fully(file, &le32_size, sizeof(le32_size), &n);
    if (ret != MB_FILE_OK) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to write MTK size field: %s",
                               mb_file_error_string(biw->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    } else if (n != sizeof(le32_size)) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                               "Unexpected EOF when writing MTK size field");
        return MB_BI_FAILED;
    }

    return MB_BI_OK;
}

int mtk_writer_get_header(MbBiWriter *biw, void *userdata,
                          MbBiHeader **header)
{
    (void) biw;
    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);

    mb_bi_header_clear(ctx->client_header);
    mb_bi_header_set_supported_fields(ctx->client_header,
                                      MTK_SUPPORTED_FIELDS);

    *header = ctx->client_header;
    return MB_BI_OK;
}

int mtk_writer_write_header(MbBiWriter *biw, void *userdata,
                            MbBiHeader *header)
{
    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);
    int ret;

    // Construct header
    memset(&ctx->hdr, 0, sizeof(ctx->hdr));
    memcpy(ctx->hdr.magic, ANDROID_BOOT_MAGIC, ANDROID_BOOT_MAGIC_SIZE);

    if (mb_bi_header_kernel_address_is_set(header)) {
        ctx->hdr.kernel_addr = mb_bi_header_kernel_address(header);
    }
    if (mb_bi_header_ramdisk_address_is_set(header)) {
        ctx->hdr.ramdisk_addr = mb_bi_header_ramdisk_address(header);
    }
    if (mb_bi_header_secondboot_address_is_set(header)) {
        ctx->hdr.second_addr = mb_bi_header_secondboot_address(header);
    }
    if (mb_bi_header_kernel_tags_address_is_set(header)) {
        ctx->hdr.tags_addr = mb_bi_header_kernel_tags_address(header);
    }
    if (mb_bi_header_page_size_is_set(header)) {
        uint32_t page_size = mb_bi_header_page_size(header);

        switch (mb_bi_header_page_size(header)) {
        case 2048:
        case 4096:
        case 8192:
        case 16384:
        case 32768:
        case 65536:
        case 131072:
            ctx->hdr.page_size = page_size;
            break;
        default:
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "Invalid page size: %" PRIu32, page_size);
            return MB_BI_FAILED;
        }
    } else {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                               "Page size field is required");
        return MB_BI_FAILED;
    }

    const char *board_name = mb_bi_header_board_name(header);
    const char *cmdline = mb_bi_header_kernel_cmdline(header);

    if (board_name) {
        if (strlen(board_name) >= sizeof(ctx->hdr.name)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "Board name too long");
            return MB_BI_FAILED;
        }

        strncpy(reinterpret_cast<char *>(ctx->hdr.name), board_name,
                sizeof(ctx->hdr.name) - 1);
        ctx->hdr.name[sizeof(ctx->hdr.name) - 1] = '\0';
    }
    if (cmdline) {
        if (strlen(cmdline) >= sizeof(ctx->hdr.cmdline)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_FILE_FORMAT,
                                   "Kernel cmdline too long");
            return MB_BI_FAILED;
        }

        strncpy(reinterpret_cast<char *>(ctx->hdr.cmdline), cmdline,
                sizeof(ctx->hdr.cmdline) - 1);
        ctx->hdr.cmdline[sizeof(ctx->hdr.cmdline) - 1] = '\0';
    }

    // TODO: UNUSED
    // TODO: ID

    // Pretend like we wrote the header. We will actually do it in
    // mtk_writer_close() when we have an accurate view of everything that
    // was written.
    ctx->pos += sizeof(AndroidHeader);

    // Clear existing entries (non should exist unless this function fails and
    // the user reattempts to call it)
    ctx->entries_len = 0;

    ret = mtk_writer_add_entry(biw, ctx, MTK_WRITER_ENTRY_BEGIN,
                               0, false, true);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MB_BI_ENTRY_MTK_KERNEL_HEADER,
                               0, false, false);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MB_BI_ENTRY_KERNEL,
                               0, false, true);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MB_BI_ENTRY_MTK_RAMDISK_HEADER,
                               0, false, false);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MB_BI_ENTRY_RAMDISK,
                               0, false, true);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MB_BI_ENTRY_SECONDBOOT,
                               0, false, true);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MB_BI_ENTRY_DEVICE_TREE,
                               0, false, true);
    if (ret != MB_BI_OK) return ret;

    ret = mtk_writer_add_entry(biw, ctx, MTK_WRITER_ENTRY_END,
                               0, false, true);
    if (ret != MB_BI_OK) return ret;

    // Start at first entry
    ctx->entry = ctx->entries;

    return MB_BI_OK;
}

int mtk_writer_get_entry(MbBiWriter *biw, void *userdata,
                         MbBiEntry **entry)
{
    // NOTE: This function must return MB_BI_FATAL if the state has been altered
    // in a non-reversible way. For exmaple, if something fails after
    // SHA1_Update(), we can't undo the effects, so we must fail fatally.

    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);
    int ret;

    if (ctx->entry->type >= 0) {
        // Update size with number of bytes written
        mtk_writer_update_size_if_unset(ctx, ctx->entry->size);

        // Check MTK header size
        ret = mtk_check_header_size(biw, ctx->entry);
        if (ret != MB_BI_OK) {
            return ret;
        }

        // Update SHA1 hash
        uint32_t le32_size = mb_htole32(ctx->entry->size);

        // Include size for everything except non-empty DT images
        if ((ctx->entry->type != MB_BI_ENTRY_DEVICE_TREE
                || ctx->entry->size > 0)
                && !SHA1_Update(&ctx->sha_ctx, &le32_size, sizeof(le32_size))) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to update SHA1 hash");
            return MB_BI_FATAL;
        }
    }

    // Finish previous entry by aligning to page
    if (ctx->entry->align) {
        ctx->pos += align_page_size<uint64_t>(ctx->pos, ctx->hdr.page_size);

        // Seek to page boundary
        ret = mb_file_seek(biw->file, ctx->pos, SEEK_SET, nullptr);
        if (ret != MB_FILE_OK) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to seek to page boundary: %s",
                                   mb_file_error_string(biw->file));
            return MB_BI_FATAL;
        }
    }

    // Advance to next entry
    mtk_writer_advance_state(ctx);

    // Update entry
    if (ctx->entry->type == MTK_WRITER_ENTRY_END) {
        return MB_BI_EOF;
    } else if (ctx->entry->type < 0) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Illegal entry type: %d", ctx->entry->type);
        return MB_BI_FATAL;
    }

    // Update starting offset
    ctx->entry->offset = ctx->pos;

    mb_bi_entry_clear(ctx->client_entry);

    if (mb_bi_entry_set_type(ctx->client_entry, ctx->entry->type) != MB_BI_OK) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Failed to set entry type");
        return MB_BI_FATAL;
    }

    *entry = ctx->client_entry;
    return MB_BI_OK;
}

int mtk_writer_write_entry(MbBiWriter *biw, void *userdata,
                           MbBiEntry *entry)
{
    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);
    int ret;

    // Use entry size if specified
    if (mb_bi_entry_size_is_set(entry)) {
        uint64_t size = mb_bi_entry_size(entry);

        if (size > UINT32_MAX) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_INVALID_ARGUMENT,
                                   "Invalid entry size: %" PRIu64, size);
            return MB_BI_FAILED;
        }

        mtk_writer_update_size_if_unset(ctx, size);

        // Check MTK header size
        ret = mtk_check_header_size(biw, ctx->entry);
        if (ret != MB_BI_OK) {
            return ret;
        }
    }

    return MB_BI_OK;
}

int mtk_writer_write_data(MbBiWriter *biw, void *userdata,
                          const void *buf, size_t buf_size,
                          size_t *bytes_written)
{
    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);
    int ret;

    // Check for overflow
    if (ctx->entry->size > UINT32_MAX - buf_size
            || ctx->pos > UINT64_MAX - buf_size) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INVALID_ARGUMENT,
                               "Overflow in entry size");
        return MB_BI_FAILED;
    }

    ret = mb_file_write_fully(biw->file, buf, buf_size, bytes_written);
    if (ret < 0) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to write data: %s",
                               mb_file_error_string(biw->file));
        return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
    } else if (*bytes_written != buf_size) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Write was truncated: %s",
                               mb_file_error_string(biw->file));
        // This is a fatal error. We must guarantee that buf_size bytes will be
        // written.
        return MB_BI_FATAL;
    }

    // We always include the image in the hash. The size is sometimes included
    // and is handled in mtk_writer_get_entry().
    if (!SHA1_Update(&ctx->sha_ctx, buf, buf_size)) {
        mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                               "Failed to update SHA1 hash");
        // This must be fatal as the write already happened and cannot be
        // reattempted
        return MB_BI_FATAL;
    }

    ctx->entry->size += buf_size;
    ctx->pos += buf_size;

    return MB_BI_OK;
}

int mtk_writer_close(MbBiWriter *biw, void *userdata)
{
    // TODO: CHECK STATE GUARANTEES

    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);
    int ret;
    size_t n;

    // If successful, finish up the boot image
    if (ctx->entry->type == MTK_WRITER_ENTRY_END) {
        // Truncate to set size
        ret = mb_file_truncate(biw->file, ctx->pos);
        if (ret < 0) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to truncate file: %s",
                                   mb_file_error_string(biw->file));
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }

        // Set sizes
        for (size_t i = 0; i < ctx->entries_len; ++i) {
            MtkWriterEntry *entry = &ctx->entries[i];
            if (entry->size_set) {
                switch (entry->type) {
                case MB_BI_ENTRY_KERNEL:
                    ctx->hdr.kernel_size = entry->size;
                    break;
                case MB_BI_ENTRY_RAMDISK:
                    ctx->hdr.ramdisk_size = entry->size;
                    break;
                case MB_BI_ENTRY_SECONDBOOT:
                    ctx->hdr.second_size = entry->size;
                    break;
                case MB_BI_ENTRY_DEVICE_TREE:
                    ctx->hdr.dt_size = entry->size;
                    break;
                }
            }
        }

        // Set ID
        unsigned char digest[SHA_DIGEST_LENGTH];
        if (!SHA1_Final(digest, &ctx->sha_ctx)) {
            mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                                   "Failed to update SHA1 hash");
            return MB_BI_FATAL;
        }
        memcpy(ctx->hdr.id, digest, SHA_DIGEST_LENGTH);

        for (size_t i = 0; i < ctx->entries_len; ++i) {
            MtkWriterEntry *entry = &ctx->entries[i];

            if (entry->type == MB_BI_ENTRY_MTK_KERNEL_HEADER) {
                ret = _mtk_header_update_size(biw, biw->file, entry->offset,
                                              ctx->hdr.kernel_size);
            } else if (entry->type == MB_BI_ENTRY_MTK_RAMDISK_HEADER) {
                ret = _mtk_header_update_size(biw, biw->file, entry->offset,
                                              ctx->hdr.ramdisk_size);
            } else {
                continue;
            }

            if (ret < 0) {
                return ret;
            }
        }

        // TODO: We need to take the performance hit and compute the SHA1 here.
        // We can't fill in the sizes in the MTK headers when we're writing
        // them. Thus, if we calculated the SHA1sum during write, it would be
        // incorrect.

        // Convert fields back to little-endian
        android_fix_header_byte_order(&ctx->hdr);

        // Seek back to beginning to write header
        ret = mb_file_seek(biw->file, 0, SEEK_SET, nullptr);
        if (ret != MB_FILE_OK) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to seek to beginning: %s",
                                   mb_file_error_string(biw->file));
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }

        // Write header
        ret = mb_file_write_fully(biw->file, &ctx->hdr, sizeof(ctx->hdr), &n);
        if (ret != MB_FILE_OK || n != sizeof(ctx->hdr)) {
            mb_bi_writer_set_error(biw, mb_file_error(biw->file),
                                   "Failed to write header: %s",
                                   mb_file_error_string(biw->file));
            return ret == MB_FILE_FATAL ? MB_BI_FATAL : MB_BI_FAILED;
        }
    }

    return MB_BI_OK;
}

int mtk_writer_free(MbBiWriter *bir, void *userdata)
{
    (void) bir;
    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(userdata);
    mb_bi_header_free(ctx->client_header);
    mb_bi_entry_free(ctx->client_entry);
    free(ctx);
    return MB_BI_OK;
}

/*!
 * \brief Set MTK boot image output format
 *
 * \param biw MbBiWriter
 *
 * \return
 *   * #MB_BI_OK if the format is successfully enabled
 *   * #MB_BI_WARN if the format is already enabled
 *   * \<= #MB_BI_FAILED if an error occurs
 */
int mb_bi_writer_set_format_mtk(MbBiWriter *biw)
{
    MtkWriterCtx *const ctx = static_cast<MtkWriterCtx *>(
            calloc(1, sizeof(MtkWriterCtx)));
    if (!ctx) {
        mb_bi_writer_set_error(biw, -errno,
                               "Failed to allocate MtkWriterCtx: %s",
                               strerror(errno));
        return MB_BI_FAILED;
    }

    if (!SHA1_Init(&ctx->sha_ctx)) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Failed to initialize SHA_CTX");
        free(ctx);
        return false;
    }

    ctx->client_header = mb_bi_header_new();
    ctx->client_entry = mb_bi_entry_new();
    if (!ctx->client_header) {
        mb_bi_writer_set_error(biw, -errno,
                               "Failed to allocate header or entry: %s",
                               strerror(errno));
        mb_bi_header_free(ctx->client_header);
        mb_bi_entry_free(ctx->client_entry);
        free(ctx);
        return MB_BI_FAILED;
    }

    return _mb_bi_writer_register_format(biw,
                                         ctx,
                                         MB_BI_FORMAT_MTK,
                                         MB_BI_FORMAT_NAME_MTK,
                                         nullptr,
                                         &mtk_writer_get_header,
                                         &mtk_writer_write_header,
                                         &mtk_writer_get_entry,
                                         &mtk_writer_write_entry,
                                         &mtk_writer_write_data,
                                         &mtk_writer_close,
                                         &mtk_writer_free);
}

MB_END_C_DECLS
