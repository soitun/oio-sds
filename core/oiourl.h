/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__core__oiourl_h
# define OIO_SDS__core__oiourl_h 1

/**
 * @addtogroup oio-api-c
 * @{
 */

#include <glib.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum oio_url_field_e
{
	OIOURL_NS=1,
	OIOURL_ACCOUNT = 2,
	OIOURL_USER = 3,
	/* DO NOT REUSE the value <4>, previously used as OIOURL_TYPE */
	OIOURL_PATH = 5,

	OIOURL_VERSION = 6,

	OIOURL_WHOLE = 7,  /* read-only */

	OIOURL_HEXID = 8,  /* read-write */
	OIOURL_CONTENTID = 9,  /* read-write */

	OIOURL_FULLPATH = 10,
	OIOURL_ROOT_HEXID = 11,

	OIOURL_BUCKET = 12,
};

/** One plus the maximum length of a namespace name
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_NSNAME 64

/** One plus the maximum length of an account name
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_ACCOUNTNAME 64

/** One plus the maximum length of a content name
 * i.e. a size enough to store the C string
 * 1024 characters for object name
 * 55 characters for potential suffixes (ex: MPU, ...)
 * 1 character for '\0'
 * 1080 characters total raised to 1088 for 64 bytes alignment sake */
#define LIMIT_LENGTH_CONTENTPATH 1088

/** One plus the maximum length of the string representation of a content version
 * i.e. a size enough to store the C string */
#define LIMIT_LENGTH_VERSION 24

/** One plus the maximum length of the string representation of a user
 *  i.e. a size enough to store the C string */
#define LIMIT_LENGTH_USER 1024


struct oio_url_s;

/**
 * Builds a URL object from a '/'-separated string.
 * The parts are parsed in that order:
 * - namespace name;
 * - account name;
 * - reference name (aka container);
 * - service type (should be empty most of the time);
 * - content name.
 *
 * Each part should be URL encoded.
 *
 * A safer alternative to using this function is calling
 * `oio_url_empty()` followed by `oio_url_set()` for each
 * part you need to set (does not require URL encoding).
 */
struct oio_url_s * oio_url_init(const char *url);

/**
 * Same as `oio_url_init`, except that the parts
 * should not be URL encoded (therefore you can't
 * use '/' inside the parts).
 */
struct oio_url_s * oio_url_init_raw(const char *url);

/** Builds an empty URL */
struct oio_url_s * oio_url_empty(void);

/** Duplicate a URL (deep copy) */
struct oio_url_s* oio_url_dup(const struct oio_url_s *u);

void oio_url_clean(struct oio_url_s *u);

void oio_url_cleanv (struct oio_url_s **tab);

void oio_url_pclean(struct oio_url_s **pu);

/**
 * Sets a part of a URL.
 * Values do not need to be URL encoded.
 *
 * @param u the URL
 * @param f the identifier of the part you wan't to set
 * @param v the value for the part (no need to URL encode)
 * @return the URL
 *
 * Note that you cannot set OIOURL_WHOLE (see `oio_url_init`).
 */
struct oio_url_s* oio_url_set(struct oio_url_s *u,
		enum oio_url_field_e f, const char *v);

void oio_url_unset(struct oio_url_s *u, enum oio_url_field_e f);

/**
 * Gets a part of a URL.
 *
 * @param u the URL
 * @param f the identifier of the part you wan't to get
 * @return the value of the field (do not free)
 *
 * The return value of `oio_url_get(url, OIOURL_WHOLE)`
 * can safely be used as input of `oio_url_init(char *url)`.
 */
const char * oio_url_get(struct oio_url_s *u, enum oio_url_field_e f);

int oio_url_has(const struct oio_url_s *u, enum oio_url_field_e f);

/** Set the container id from its binary representation.
 * Use oio_url_set(u, OIOURL_CONTENTID, id) to set it with an hexadecimal str.
 * @param id must be oio_url_get_id_size() bytes long */
void oio_url_set_id(struct oio_url_s *u, const void *id);

/* the returned value points to an array of oio_url_get_id_size() bytes long. */
const void* oio_url_get_id(struct oio_url_s *u);

/* returns the number of bytes */
size_t oio_url_get_id_size(struct oio_url_s *u);

/** Returns whether all the mandatory components for a path are present */
int oio_url_has_fq_path (const struct oio_url_s *u);

/** Returns whether all the mandatory components for a container are present */
int oio_url_has_fq_container (const struct oio_url_s *u);

/** Validate contains of oio_url
 *
 * @param u the URL
 * @param n the namespace (optional)
 * @param e will contains faulty field
 * @return true if valid
*/
gboolean oio_url_check(const struct oio_url_s *u, const char *n, const gchar **e);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /*OIO_SDS__core__oiourl_h*/
