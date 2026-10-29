/*
MASTER_LIST.H

OpenCE's master servers, read by the server browser (master_list.c).

OpenCE's dedicated servers publish to its master servers rather than to the
signalling brokers' lobby (OpenCE's docs/master_protocol.md, "The list"), so
a build that only reads the brokers never sees them. While the server browser
is open (p2p_lobby_browse), each master of network.masters_file is asked for
its list (GET /v1/servers) every MASTER_LIST_ROUND_SECONDS, and on Refresh,
on a thread of this file's. A list is taken only if its Ed25519 signature
(the Signature header, "ed25519=<base64>") checks with the key pinned for
that master, the master names that key (Signature-Key), and it is fresh;
each entry holds the host-signed listing the host publishes to the brokers,
which p2p_lobby.c checks again (p2p_lobby_take_master_listing), so a master
can't claim anything the host did not sign. The game is then joined by its
invite, through the brokers, as any other listed game.

network.master_servers turns it off. Builds without the game browser's HTTPS
(HALO_GAME_BROWSER) have no master servers: these do nothing there.
*/

#ifndef __HALO_LINUX_MASTER_LIST_H
#define __HALO_LINUX_MASTER_LIST_H

enum
{
	MASTER_LIST_MAXIMUM_MASTERS = 4,
	MASTER_LIST_KEY_SIZE = 32,
	MASTER_LIST_URL_SIZE = 256,
	MASTER_LIST_ROUND_SECONDS = 30,
	/* a list older than this is refused (a replayed one), and one dated
	further ahead of this machine's clock */
	MASTER_LIST_FRESH_SECONDS = 300,
};

/* the server browser open (its masters asked every round) or closed */
void master_list_browse(int on);
/* Refresh: asked again now */
void master_list_refresh(void);

/* ---------- pure (tools/test_master_list.py tests these) */

/* the masters of a masters.txt's text ("https://host ed25519:<64 hex>" on
each line, "#" starting a comment): their URLs and keys, up to maximum; how
many */
int master_list_parse(const char *text, char (*urls)[MASTER_LIST_URL_SIZE],
	unsigned char (*keys)[MASTER_LIST_KEY_SIZE], int maximum);
/* the official masters (OpenCE's, built in), for a masters file that names
none: how many */
int master_list_defaults(char (*urls)[MASTER_LIST_URL_SIZE], unsigned char (*keys)[MASTER_LIST_KEY_SIZE],
	int maximum);
/* a signed list's checks: the Signature header's value over the body with
the key, the Signature-Key header's (the key's id), and the body's protocol,
master key id and time (now: Unix seconds); 1 if it is a list to take, else
0 with why */
int master_list_verify(const char *body, unsigned long size, const char *signature_header, const char *key_header,
	const unsigned char *key, unsigned long now, char *why, int why_size);
/* a list's servers: for each entry, its listing's bytes (decoded from
base64) and whether the master says it is a dedicated server's, given to
take; how many entries it gave */
int master_list_entries(const char *body, unsigned long size,
	void (*take)(const unsigned char *listing, int listing_size, int dedicated, void *context), void *context);

#endif
