/*
Copyright (c) 2018, Klaus Pedersen <klaus@brightstorm.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the DHLEASE project.
*/

#define TOK_INVALID_TOKEN	0
#define TOK_LEASE		1
#define TOK_HARDWARE		2
#define TOK_ETHERNET		3
#define TOK_STARTS		4
#define TOK_ENDS		5
#define TOK_CLIENT_HOSTNAME	6
#define TOK_ABANDONED		7
#define CHAR_CURLY_BRACE_START	'{'
#define CHAR_CURLY_BRACE_END	'}'
#define CHAR_SEMICOLON		';'
#define DEFAULT_LEASE_FILE	"/var/db/dhcpd.leases"

static void   usage(void);
static void   open_lease_file(const char *filename);
static void   parse_lease_file(void);
static void   parse_ip_address(void);
static void   parse_ethernet_address(void);
static void   parse_client_hostname(void);
static void   read_string_to_semicolon(void);
static void   check_block_scope(void);
static void   output_leases(const size_t cltlen, const size_t iplen, const size_t maclen, const size_t slen, const size_t elen);
static void   seek_char(const unsigned char chr);
static char   *time_to_string(const time_t *time);
static time_t parse_date_string(void);
static time_t string_to_time(const char *datestr);
static int    compare_time(const time_t t1, const time_t t2);
static int    has_lease_expired(const time_t tend);
static int    get_token(int *count, int *found);
static int    get_char(void);
static int    keyword_cmp(const void *p1, const void *p2);
static int    lookup(char *value);
static int    peek_char(void);
static int    error(const char *fmt, ...);
static int    match_partial_string(const char *src, const char *search);

static TAILQ_HEAD(thead, lease_t) head = TAILQ_HEAD_INITIALIZER(head);

struct lease_t {
	time_t		start;
	time_t		end;
	char		*hostname;
	char		*client;
	char		*ipaddr;
	char		*macaddr;
	int		abandoned;
	int		expired;
	TAILQ_ENTRY(lease_t) entities;
};
