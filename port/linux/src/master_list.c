/*
MASTER_LIST.C

OpenCE's master servers, read by the server browser (master_list.h).

The list's format (OpenCE's docs/master_protocol.md, version 1):

	{"protocol":1,"master":{"key_id":"<16 hex>","time":<unix seconds>,...},
	 "servers":[{"listing":"<base64>","dedicated":true,...},...]}

Members this file does not know are skipped, so later versions can add
some. The JSON is read in place (the body is signed as it came) by a small
reader of its own: the list's few members are all this file needs.
*/

#include "platform.h"
#include "master_list.h"
#include "p2p_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
	MAXIMUM_ENTRIES = 512,
	MAXIMUM_LISTING = 400,
	/* (deeper nesting than a list has is refused, not followed) */
	MAXIMUM_DEPTH = 32,
};

static int hex_digit(char character)
{
	if (character >= '0' && character <= '9')
		return character - '0';
	if (character >= 'a' && character <= 'f')
		return character - 'a' + 10;
	if (character >= 'A' && character <= 'F')
		return character - 'A' + 10;
	return -1;
}

/* ---------- the masters */

/* whether a master's URL may be asked: https, or plain http to this machine
alone (a test's master): http://127.0.0.1 or http://localhost, then a port,
a path or nothing */
static int url_allowed(const char *url)
{
	static const char *const loopbacks[] = { "http://127.0.0.1", "http://localhost" };
	size_t index;

	if (!strncmp(url, "https://", 8))
		return url[8] != 0;
	for (index = 0; index < sizeof(loopbacks) / sizeof(loopbacks[0]); index++)
	{
		size_t length = strlen(loopbacks[index]);

		if (!strncmp(url, loopbacks[index], length) && (!url[length] || url[length] == ':' || url[length] == '/'))
			return 1;
	}
	return 0;
}

/* one master (a URL and its "ed25519:<hex>" key) checked and kept at index: 1 */
static int keep(const char *url, const char *key, char (*urls)[MASTER_LIST_URL_SIZE],
	unsigned char (*keys)[MASTER_LIST_KEY_SIZE], int index)
{
	int digit;
	size_t length;

	if (!url_allowed(url) || strlen(url) >= MASTER_LIST_URL_SIZE || strncmp(key, "ed25519:", 8) ||
		strlen(key) != 8 + 2 * MASTER_LIST_KEY_SIZE)
	{
		return 0;
	}
	for (digit = 0; digit < MASTER_LIST_KEY_SIZE; digit++)
	{
		int high = hex_digit(key[8 + 2 * digit]), low = hex_digit(key[8 + 2 * digit + 1]);

		if (high < 0 || low < 0)
			return 0;
		keys[index][digit] = (unsigned char)(high << 4 | low);
	}
	snprintf(urls[index], MASTER_LIST_URL_SIZE, "%s", url);
	/* (no slash at the end: the path is the URL's and /v1/servers) */
	while ((length = strlen(urls[index])) > 8 && urls[index][length - 1] == '/')
		urls[index][length - 1] = 0;
	return 1;
}

int master_list_parse(const char *text, char (*urls)[MASTER_LIST_URL_SIZE],
	unsigned char (*keys)[MASTER_LIST_KEY_SIZE], int maximum)
{
	const char *line;
	int count = 0;

	for (line = text ? text : ""; *line && count < maximum;)
	{
		const char *end = line + strcspn(line, "\n");
		char copy[512];
		char url[MASTER_LIST_URL_SIZE], key[96];

		snprintf(copy, sizeof(copy), "%.*s", (int)(end - line), line);
		copy[strcspn(copy, "#\r")] = 0;
		line = *end ? end + 1 : end;
		if (sscanf(copy, "%255s %95s", url, key) == 2)
			count += keep(url, key, urls, keys, count);
	}
	return count;
}

int master_list_defaults(char (*urls)[MASTER_LIST_URL_SIZE], unsigned char (*keys)[MASTER_LIST_KEY_SIZE],
	int maximum)
{
	/* (OpenCE's official master, as its master_list_read_defaults has it) */
	static const struct
	{
		const char *url;
		const char *key;
	} masters[] =
	{
		{ "https://master.opencommunityedition.com",
			"ed25519:89f4eda71229f11f3538679f49ef7fb0c2b407b380093f7f4fe02105b92225aa" },
	};
	int index, count = 0;

	for (index = 0; index < (int)(sizeof(masters) / sizeof(masters[0])) && count < maximum; index++)
		count += keep(masters[index].url, masters[index].key, urls, keys, count);
	return count;
}

/* ---------- a small JSON reader (RFC 8259), over the text in place */

struct json
{
	const char *at;
	const char *end;
};

static void json_space(struct json *json)
{
	while (json->at < json->end && (*json->at == ' ' || *json->at == '\t' || *json->at == '\n' || *json->at == '\r'))
		json->at++;
}

/* past a string (at its opening quote): 1, else 0 */
static int json_skip_string(struct json *json)
{
	if (json->at >= json->end || *json->at != '"')
		return 0;
	for (json->at++; json->at < json->end; json->at++)
	{
		if (*json->at == '\\')
		{
			if (++json->at >= json->end)
				return 0;
		}
		else if (*json->at == '"')
		{
			json->at++;
			return 1;
		}
		else if ((unsigned char)*json->at < 0x20)
		{
			return 0;
		}
	}
	return 0;
}

/* past a value: 1, else 0 (a value that does not end, or nests too deep) */
static int json_skip_value(struct json *json)
{
	int depth = 0;

	json_space(json);
	do
	{
		if (json->at >= json->end)
			return 0;
		switch (*json->at)
		{
		case '"':
			if (!json_skip_string(json))
				return 0;
			break;
		case '{':
		case '[':
			if (++depth > MAXIMUM_DEPTH)
				return 0;
			json->at++;
			break;
		case '}':
		case ']':
			if (--depth < 0)
				return 0;
			json->at++;
			break;
		case ',':
		case ':':
			/* (inside a container: its separators) */
			if (!depth)
				return 0;
			json->at++;
			break;
		default:
			/* a number, true, false or null */
			if (!strchr("-0123456789tfn", *json->at))
				return 0;
			while (json->at < json->end && !strchr(",:]} \t\r\n", *json->at))
				json->at++;
			break;
		}
		json_space(json);
	} while (depth > 0);
	return 1;
}

/* an object's member (the object's text at json): its value's start in
value, 1; 0 if there is none or the object does not read */
static int json_member(struct json object, const char *name, struct json *value)
{
	size_t length = strlen(name);

	json_space(&object);
	if (object.at >= object.end || *object.at != '{')
		return 0;
	object.at++;
	json_space(&object);
	if (object.at < object.end && *object.at == '}')
		return 0;
	while (object.at < object.end)
	{
		const char *key = object.at + 1;
		int same;

		if (!json_skip_string(&object))
			return 0;
		/* (a name with escapes is not one of ours: compared as it is) */
		same = (size_t)(object.at - 1 - key) == length && !memcmp(key, name, length);
		json_space(&object);
		if (object.at >= object.end || *object.at != ':')
			return 0;
		object.at++;
		json_space(&object);
		if (same)
		{
			*value = object;
			return 1;
		}
		if (!json_skip_value(&object))
			return 0;
		if (object.at < object.end && *object.at == ',')
		{
			object.at++;
			json_space(&object);
			continue;
		}
		return 0;
	}
	return 0;
}

/* an array's elements in turn: *cursor starts as the array (its '['); each
call puts the next element in element, 1, or 0 at the end */
static int json_next_element(struct json *cursor, int *started, struct json *element)
{
	json_space(cursor);
	if (!*started)
	{
		if (cursor->at >= cursor->end || *cursor->at != '[')
			return 0;
		cursor->at++;
		*started = 1;
		json_space(cursor);
		if (cursor->at < cursor->end && *cursor->at == ']')
			return 0;
	}
	else
	{
		if (cursor->at >= cursor->end || *cursor->at != ',')
			return 0;
		cursor->at++;
		json_space(cursor);
	}
	*element = *cursor;
	return json_skip_value(cursor);
}

/* a string value into text (printable ASCII; others, and escapes of them,
'?'), cut to size: 1, else 0 */
static int json_string(struct json value, char *text, int size)
{
	int used = 0;

	json_space(&value);
	if (size <= 0 || value.at >= value.end || *value.at != '"')
		return 0;
	for (value.at++; value.at < value.end && *value.at != '"'; value.at++)
	{
		char character = *value.at;

		if (character == '\\')
		{
			if (++value.at >= value.end)
				return 0;
			switch (*value.at)
			{
			case '"': character = '"'; break;
			case '\\': character = '\\'; break;
			case '/': character = '/'; break;
			case 'u':
				character = '?';
				if (value.end - value.at > 4)
				{
					int digit, code = 0;

					for (digit = 1; digit <= 4; digit++)
					{
						int nibble = hex_digit(value.at[digit]);

						if (nibble < 0)
							return 0;
						code = code << 4 | nibble;
					}
					value.at += 4;
					if (code >= 0x20 && code < 0x7F)
						character = (char)code;
				}
				else
				{
					return 0;
				}
				break;
			default: character = '?'; break;
			}
		}
		else if ((unsigned char)character < 0x20 || (unsigned char)character >= 0x7F)
		{
			character = '?';
		}
		if (used < size - 1)
			text[used++] = character;
	}
	text[used] = 0;
	return value.at < value.end;
}

/* a number value: 1, else 0 */
static int json_number(struct json value, double *number)
{
	char copy[64];
	char *end;
	int length = 0;

	json_space(&value);
	while (value.at + length < value.end && length < (int)sizeof(copy) - 1 &&
		strchr("+-.0123456789eE", value.at[length]))
	{
		length++;
	}
	if (!length)
		return 0;
	memcpy(copy, value.at, (size_t)length);
	copy[length] = 0;
	*number = strtod(copy, &end);
	return end != copy;
}

/* a boolean value: 1, else 0 */
static int json_boolean(struct json value, int *boolean)
{
	json_space(&value);
	if (value.end - value.at >= 4 && !memcmp(value.at, "true", 4))
		*boolean = 1;
	else if (value.end - value.at >= 5 && !memcmp(value.at, "false", 5))
		*boolean = 0;
	else
		return 0;
	return 1;
}

/* standard base64 (RFC 4648 section 4, with padding) into bytes: their
count, or -1 */
static int base64_decode(const char *text, unsigned char *bytes, int maximum)
{
	unsigned int bits = 0;
	int bit_count = 0, count = 0;

	for (; *text && *text != '='; text++)
	{
		const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		const char *found = strchr(alphabet, *text);

		if (!found)
			return -1;
		bits = bits << 6 | (unsigned int)(found - alphabet);
		bit_count += 6;
		if (bit_count >= 8)
		{
			bit_count -= 8;
			if (count >= maximum)
				return -1;
			bytes[count++] = (unsigned char)(bits >> bit_count);
		}
	}
	while (*text == '=')
		text++;
	return *text ? -1 : count;
}

/* ---------- a list */

int master_list_verify(const char *body, unsigned long size, const char *signature_header, const char *key_header,
	const unsigned char *key, unsigned long now, char *why, int why_size)
{
	unsigned char signature[P2P_SIGNATURE_SIZE + 4];
	unsigned char digest[P2P_SHA256_SIZE];
	char key_id[2 * 8 + 1];
	char text[96];
	struct json json, master, member;
	double protocol, time_value;

	p2p_sha256(key, MASTER_LIST_KEY_SIZE, digest);
	p2p_hex(digest, 8, key_id);
	if (!signature_header || strncmp(signature_header, "ed25519=", 8) ||
		base64_decode(signature_header + 8, signature, (int)sizeof(signature)) != P2P_SIGNATURE_SIZE)
	{
		snprintf(why, (size_t)why_size, "no signature");
		return 0;
	}
	/* (the key the master says it signed with must be the one pinned: a list
	without it is refused too) */
	if (!key_header || strcmp(key_header, key_id))
	{
		snprintf(why, (size_t)why_size, "signed by another key (%.16s)", key_header && *key_header ? key_header :
			"none said");
		return 0;
	}
	if (size > 0x7FFFFFFF || !p2p_ed25519_verify(key, body, (int)size, signature))
	{
		snprintf(why, (size_t)why_size, "its signature does not check");
		return 0;
	}
	json.at = body;
	json.end = body + size;
	if (!json_member(json, "protocol", &member) || !json_number(member, &protocol) || protocol != 1 ||
		!json_member(json, "master", &master) || !json_member(master, "key_id", &member) ||
		!json_string(member, text, sizeof(text)) || strcmp(text, key_id) ||
		!json_member(master, "time", &member) || !json_number(member, &time_value))
	{
		snprintf(why, (size_t)why_size, "not a list of protocol 1 by this master");
		return 0;
	}
	if ((double)now - time_value > MASTER_LIST_FRESH_SECONDS)
	{
		snprintf(why, (size_t)why_size, "a list %.0f seconds old", (double)now - time_value);
		return 0;
	}
	if (time_value - (double)now > MASTER_LIST_FRESH_SECONDS)
	{
		snprintf(why, (size_t)why_size, "a list dated %.0f seconds ahead (this machine's clock is wrong, or the "
			"master's)", time_value - (double)now);
		return 0;
	}
	return 1;
}

int master_list_entries(const char *body, unsigned long size,
	void (*take)(const unsigned char *listing, int listing_size, int dedicated, void *context), void *context)
{
	struct json json, servers, entry, member;
	int started = 0, given = 0, index;

	json.at = body;
	json.end = body + size;
	if (!json_member(json, "servers", &servers))
		return 0;
	for (index = 0; index < MAXIMUM_ENTRIES && json_next_element(&servers, &started, &entry); index++)
	{
		char listing_text[4 * ((MAXIMUM_LISTING + 2) / 3) + 8];
		unsigned char listing[MAXIMUM_LISTING];
		int listing_size, dedicated = 0;

		/* (an entry that is not one is skipped, not the list) */
		if (!json_member(entry, "listing", &member) || !json_string(member, listing_text, sizeof(listing_text)))
			continue;
		listing_size = base64_decode(listing_text, listing, (int)sizeof(listing));
		if (listing_size <= 0)
			continue;
		/* (a dedicated server's, as the entry says; a player's public game a
		publisher key published is not) */
		if (json_member(entry, "dedicated", &member))
			json_boolean(member, &dedicated);
		take(listing, listing_size, dedicated, context);
		given++;
	}
	return given;
}

/* ---------- asking the masters (the game browser's HTTPS) */

#ifdef HALO_GAME_BROWSER

#include "port_config.h"
#include "browser_http.h"

#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

enum
{
	MAXIMUM_ANSWER = 1024 * 1024,
	HEADERS_SIZE = 8192,
};

static struct
{
	pthread_mutex_t lock;
	pthread_cond_t wake;
	/* each opening of the browser's: a thread of an earlier one (still
	asking a master when the browser was closed and opened again) ends at
	its next look, without being waited for */
	unsigned long generation;
	int browsing;
	int refresh;
} list = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0, 0 };

/* waits on the condition for seconds at most (under list.lock) */
static void wait_seconds(int seconds)
{
	struct timespec until;

	clock_gettime(CLOCK_REALTIME, &until);
	until.tv_sec += seconds;
	pthread_cond_timedwait(&list.wake, &list.lock, &until);
}

/* a response's header's value, from its "Name: value" lines */
static void header_value(const char *headers, const char *name, char *value, int size)
{
	size_t length = strlen(name);
	const char *line = headers;

	value[0] = 0;
	while (line && *line)
	{
		size_t index;

		for (index = 0; index < length && line[index] &&
			tolower((unsigned char)line[index]) == tolower((unsigned char)name[index]); index++)
			;
		if (index == length && line[length] == ':')
		{
			const char *start = line + length + 1;

			while (*start == ' ' || *start == '\t')
				start++;
			snprintf(value, (size_t)size, "%.*s", (int)strcspn(start, "\r\n"), start);
			return;
		}
		line = strchr(line, '\n');
		if (line)
			line++;
	}
}

/* the masters to ask: network.masters_file's (beside config.toml unless a
full path); OpenCE's official one when it names none */
static int read_masters(char (*urls)[MASTER_LIST_URL_SIZE], unsigned char (*keys)[MASTER_LIST_KEY_SIZE])
{
	const char *name = config_string("network.masters_file");
	char path[1024];
	char *text = NULL;
	size_t length = 0;
	int count = 0;

	if (name[0])
	{
		if (name[0] == '/' || name[0] == '\\' || (name[0] && name[1] == ':'))
			snprintf(path, sizeof(path), "%s", name);
		else
		{
			config_folder(path, sizeof(path));
			snprintf(path + strlen(path), sizeof(path) - strlen(path), "%s", name);
		}
		text = config_file_read(path, &length);
	}
	if (text)
	{
		count = master_list_parse(text, urls, keys, MASTER_LIST_MAXIMUM_MASTERS);
		free(text);
	}
	if (!count)
		count = master_list_defaults(urls, keys, MASTER_LIST_MAXIMUM_MASTERS);
	return count;
}

static void take_entry(const unsigned char *listing, int listing_size, int dedicated, void *context)
{
	int *taken = context;

	*taken += p2p_lobby_take_master_listing(listing, listing_size, dedicated);
}

/* one master asked, its list given to the lobby */
static void ask_master(const char *base, const unsigned char *key, char *body, char *headers)
{
	char url[MASTER_LIST_URL_SIZE + 32];
	char error[256], why[160], signature[128], key_id[40];
	int status, taken = 0;

	snprintf(url, sizeof(url), "%s/v1/servers", base);
	status = posix_browser_get_with_headers(url, body, MAXIMUM_ANSWER + 1, headers, HEADERS_SIZE, error,
		sizeof(error));
	if (!status)
	{
		platform_log("Server browser: no answer from the master server %s: %s", base, error);
		return;
	}
	if (status != 200)
	{
		platform_log("Server browser: the master server %s answered %d", base, status);
		return;
	}
	header_value(headers, "Signature", signature, sizeof(signature));
	header_value(headers, "Signature-Key", key_id, sizeof(key_id));
	if (!master_list_verify(body, (unsigned long)strlen(body), signature, key_id, key, (unsigned long)time(NULL), why,
		sizeof(why)))
	{
		platform_log("Server browser: the master server %s's list refused: %s", base, why);
		return;
	}
	master_list_entries(body, (unsigned long)strlen(body), take_entry, &taken);
	platform_log("Server browser: the master server %s lists %d game%s", base, taken, taken == 1 ? "" : "s");
}

/* under list.lock: whether the thread of that opening goes on */
static int list_current(unsigned long generation)
{
	return list.browsing && list.generation == generation;
}

static void *list_thread_main(void *argument)
{
	unsigned long generation = (unsigned long)(uintptr_t)argument;
	char urls[MASTER_LIST_MAXIMUM_MASTERS][MASTER_LIST_URL_SIZE];
	unsigned char keys[MASTER_LIST_MAXIMUM_MASTERS][MASTER_LIST_KEY_SIZE];
	char *body = malloc(MAXIMUM_ANSWER + 1);
	char *headers = malloc(HEADERS_SIZE);
	int count = read_masters(urls, keys);

	pthread_mutex_lock(&list.lock);
	while (body && headers && list_current(generation))
	{
		int index;

		list.refresh = 0;
		pthread_mutex_unlock(&list.lock);
		for (index = 0; index < count; index++)
		{
			ask_master(urls[index], keys[index], body, headers);
			pthread_mutex_lock(&list.lock);
			if (!list_current(generation))
			{
				pthread_mutex_unlock(&list.lock);
				break;
			}
			pthread_mutex_unlock(&list.lock);
		}
		pthread_mutex_lock(&list.lock);
		if (list_current(generation) && !list.refresh)
			wait_seconds(MASTER_LIST_ROUND_SECONDS);
	}
	pthread_mutex_unlock(&list.lock);
	free(body);
	free(headers);
	return NULL;
}

void master_list_browse(int on)
{
	if (on && (!config_boolean("network.master_servers") || !config_boolean("network.online")))
		on = 0;
	pthread_mutex_lock(&list.lock);
	if (on && !list.browsing)
	{
		pthread_t thread;

		list.browsing = 1;
		list.generation++;
		if (pthread_create(&thread, NULL, list_thread_main, (void *)(uintptr_t)list.generation) == 0)
			pthread_detach(thread);
		else
			list.browsing = 0;
	}
	else if (!on && list.browsing)
	{
		list.browsing = 0;
		pthread_cond_broadcast(&list.wake);
	}
	pthread_mutex_unlock(&list.lock);
}

void master_list_refresh(void)
{
	pthread_mutex_lock(&list.lock);
	list.refresh = 1;
	pthread_cond_broadcast(&list.wake);
	pthread_mutex_unlock(&list.lock);
}

#else

/* (no HTTPS in this build: no master servers) */
void master_list_browse(int on)
{
	(void)on;
}

void master_list_refresh(void)
{
}

#endif
