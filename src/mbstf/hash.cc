/*
License: 5G-MAG Public License (v1.0)
Copyright: (C) 2024 British Broadcasting Corporation

For full license terms please see the LICENSE file distributed with this
program. If this file is missing then the license can be retrieved from
https://drive.google.com/file/d/1cinCiA778IErENZ3JN52VFW-1ffHpx7Z/view
*/

#include "hash.hh"

char *calculate_hash(const char *buf) {
    unsigned char *result = NULL;
    size_t result_len;
    gnutls_datum_t data;
    char *hash;
    size_t i;

    result_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
    data.data = (unsigned char *)buf;
    data.size = strlen(buf);
    result = (unsigned char *)ogs_calloc(1, result_len);
    ogs_assert(result);
    hash = (char *)ogs_calloc(1, result_len*2 + 1);
    ogs_assert(hash);
    gnutls_fingerprint(GNUTLS_DIG_SHA256, &data, result, &result_len);
    for (i = 0; i < result_len; i++)
    {
        sprintf(hash+i*2, "%02x", result[i]);
    }
    ogs_free(result);
    return hash;
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
