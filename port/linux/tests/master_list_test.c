/*
MASTER_LIST_TEST.C

Tests of the server browser's reading of OpenCE's master servers
(port/linux/src/master_list.c): masters.txt's lines, the official master,
a list's signature, key and freshness checks, and its entries' listings.
Built by tools/test_master_list.py.
*/

#include "p2p_internal.h"
#include "master_list.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- stand-ins */

pthread_mutex_t p2p_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned char random_next = 1;

void posix_random_bytes(void *buffer, unsigned long size)
{
	unsigned char *bytes = buffer;
	unsigned long index;

	for (index = 0; index < size; index++)
		bytes[index] = random_next++;
}

void platform_log(const char *format, ...)
{
	(void)format;
}

void p2p_hex(const unsigned char *bytes, int size, char *text)
{
	static const char digits[] = "0123456789abcdef";
	int index;

	for (index = 0; index < size; index++)
	{
		text[2 * index] = digits[bytes[index] >> 4];
		text[2 * index + 1] = digits[bytes[index] & 15];
	}
	text[2 * size] = 0;
}

int p2p_lobby_take_master_listing(const unsigned char *payload, int size, int dedicated)
{
	(void)payload;
	(void)size;
	(void)dedicated;
	return 0;
}

/* ---------- checks */

static int failures;

static void check(int condition, const char *what)
{
	if (!condition)
	{
		printf("FAIL: %s\n", what);
		failures++;
	}
}

static void base64(const unsigned char *bytes, int size, char *text)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int index, used = 0;

	for (index = 0; index < size; index += 3)
	{
		unsigned int value = (unsigned int)bytes[index] << 16 |
			(index + 1 < size ? (unsigned int)bytes[index + 1] << 8 : 0) | (index + 2 < size ? bytes[index + 2] : 0);

		text[used++] = alphabet[value >> 18 & 63];
		text[used++] = alphabet[value >> 12 & 63];
		text[used++] = index + 1 < size ? alphabet[value >> 6 & 63] : '=';
		text[used++] = index + 2 < size ? alphabet[value & 63] : '=';
	}
	text[used] = 0;
}

struct taken
{
	int count;
	int sizes[8];
	unsigned char first[8];
	int dedicated[8];
};

static void take(const unsigned char *listing, int listing_size, int dedicated, void *context)
{
	struct taken *taken = context;

	if (taken->count < 8)
	{
		taken->sizes[taken->count] = listing_size;
		taken->first[taken->count] = listing[0];
		taken->dedicated[taken->count] = dedicated;
	}
	taken->count++;
}

static void test_masters_file(void)
{
	char urls[MASTER_LIST_MAXIMUM_MASTERS][MASTER_LIST_URL_SIZE];
	unsigned char keys[MASTER_LIST_MAXIMUM_MASTERS][MASTER_LIST_KEY_SIZE];
	const char *text =
		"# OpenCE's masters\n"
		"https://master.example.org/ ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\r\n"
		"http://master.example.org ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n"
		"http://127.0.0.1:8080 ed25519:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff # test\n"
		"http://127.0.0.1.example.net ed25519:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n"
		"https://short.example.org ed25519:0011\n"
		"https://nothex.example.org ed25519:zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
	int count = master_list_parse(text, urls, keys, MASTER_LIST_MAXIMUM_MASTERS);

	check(count == 2, "masters.txt: an https master and a loopback one");
	check(count >= 1 && !strcmp(urls[0], "https://master.example.org"), "masters.txt: the URL without its slash");
	check(count >= 1 && keys[0][0] == 0xd7 && keys[0][31] == 0x1a, "masters.txt: the key");
	check(count >= 2 && !strcmp(urls[1], "http://127.0.0.1:8080"), "masters.txt: a test's master on this machine");
	check(master_list_parse("# nothing\n\n", urls, keys, MASTER_LIST_MAXIMUM_MASTERS) == 0, "masters.txt: none");
	check(master_list_defaults(urls, keys, MASTER_LIST_MAXIMUM_MASTERS) == 1 &&
		!strcmp(urls[0], "https://master.opencommunityedition.com") && keys[0][0] == 0x89 && keys[0][31] == 0xaa,
		"the official master");
}

/* a list as a master signs it: its body, and its headers' values */
static void make_list(const unsigned char *seed, const unsigned char *public_key, unsigned long time_value,
	const char *servers, char *body, int size, char *signature_header, char *key_header)
{
	unsigned char digest[P2P_SHA256_SIZE];
	unsigned char signature[P2P_SIGNATURE_SIZE];
	char key_id[17];
	char text[128];

	p2p_sha256(public_key, MASTER_LIST_KEY_SIZE, digest);
	p2p_hex(digest, 8, key_id);
	snprintf(body, (size_t)size,
		"{ \"protocol\": 1, \"master\": {\"key_id\":\"%s\", \"name\": \"Test \\\"master\\\"\", \"time\": %lu, "
		"\"extra\": [1, {\"a\": [true, null]}]}, \"servers\": %s }", key_id, time_value, servers);
	p2p_ed25519_sign(seed, public_key, body, (int)strlen(body), signature);
	base64(signature, P2P_SIGNATURE_SIZE, text);
	sprintf(signature_header, "ed25519=%s", text);
	strcpy(key_header, key_id);
}

static void test_lists(void)
{
	unsigned char seed[32], public_key[32], x25519[32], other_seed[32], other_key[32];
	unsigned char listing_one[200], listing_two[300];
	char listing_one_text[400], listing_two_text[500];
	char servers[2048], body[4096], signature_header[128], key_header[32], why[160];
	unsigned long now = 1760900000;
	struct taken taken;
	int index;

	for (index = 0; index < 32; index++)
	{
		seed[index] = (unsigned char)(index * 7 + 1);
		other_seed[index] = (unsigned char)(index * 5 + 3);
	}
	p2p_ed25519_public(seed, public_key, x25519);
	p2p_ed25519_public(other_seed, other_key, x25519);
	for (index = 0; index < (int)sizeof(listing_one); index++)
		listing_one[index] = (unsigned char)(index ^ 0x5A);
	for (index = 0; index < (int)sizeof(listing_two); index++)
		listing_two[index] = (unsigned char)(255 - index);
	base64(listing_one, sizeof(listing_one), listing_one_text);
	base64(listing_two, sizeof(listing_two), listing_two_text);
	snprintf(servers, sizeof(servers),
		"[{\"server_id\":\"4c5f15237c866f6f\",\"listing\":\"%s\",\"dedicated\":true,\"publisher\":{\"name\":\"a\\u00e9b\"},"
		"\"region\":\"eu\",\"network_version\":39},"
		"{\"listing\":42},"
		"{\"note\":\"no listing\"},"
		"{\"listing\":\"!!!not base64\"},"
		"{\"dedicated\":false, \"listing\":\"%s\"}]",
		listing_one_text, listing_two_text);
	make_list(seed, public_key, now - 10, servers, body, sizeof(body), signature_header, key_header);

	check(master_list_verify(body, strlen(body), signature_header, key_header, public_key, now, why, sizeof(why)),
		"a good list is taken");
	memset(&taken, 0, sizeof(taken));
	check(master_list_entries(body, strlen(body), take, &taken) == 2 && taken.count == 2, "its two good entries");
	check(taken.sizes[0] == (int)sizeof(listing_one) && taken.first[0] == listing_one[0] && taken.dedicated[0] == 1,
		"the first: its listing, a dedicated server's");
	check(taken.sizes[1] == (int)sizeof(listing_two) && taken.first[1] == listing_two[0] && taken.dedicated[1] == 0,
		"the second: its listing, a player's game");

	check(!master_list_verify(body, strlen(body), signature_header, key_header, other_key, now, why, sizeof(why)),
		"a list signed by another key than the pinned one is refused");
	check(!master_list_verify(body, strlen(body), signature_header, "0000000000000000", public_key, now, why,
		sizeof(why)), "a list naming another key is refused");
	check(!master_list_verify(body, strlen(body), signature_header, NULL, public_key, now, why, sizeof(why)),
		"a list naming no key is refused");
	check(!master_list_verify(body, strlen(body), "", key_header, public_key, now, why, sizeof(why)),
		"an unsigned list is refused");
	body[strlen(body) - 3] = ' ';
	check(!master_list_verify(body, strlen(body), signature_header, key_header, public_key, now, why, sizeof(why)),
		"a changed list is refused");

	make_list(seed, public_key, now - MASTER_LIST_FRESH_SECONDS - 5, "[]", body, sizeof(body), signature_header,
		key_header);
	check(!master_list_verify(body, strlen(body), signature_header, key_header, public_key, now, why, sizeof(why)),
		"a stale list is refused");
	make_list(seed, public_key, now + MASTER_LIST_FRESH_SECONDS + 5, "[]", body, sizeof(body), signature_header,
		key_header);
	check(!master_list_verify(body, strlen(body), signature_header, key_header, public_key, now, why, sizeof(why)),
		"a list dated ahead is refused");
	make_list(seed, public_key, now, "[]", body, sizeof(body), signature_header, key_header);
	check(master_list_verify(body, strlen(body), signature_header, key_header, public_key, now, why, sizeof(why)),
		"an empty list is a list");
	memset(&taken, 0, sizeof(taken));
	check(master_list_entries(body, strlen(body), take, &taken) == 0 && taken.count == 0, "with no entries");

	/* (not JSON at all, and a list that never ends: nothing taken) */
	memset(&taken, 0, sizeof(taken));
	{
	const char *cut = "{\"servers\": [{\"listing\": \"AAAA\"";

	check(master_list_entries(cut, strlen(cut), take, &taken) == 0, "a cut list");
	check(master_list_entries("<html>", 6, take, &taken) == 0 && taken.count == 0, "not a list");
	}
}

int main(void)
{
	test_masters_file();
	test_lists();
	if (failures)
	{
		printf("%d failed\n", failures);
		return 1;
	}
	printf("PASS\n");
	return 0;
}
