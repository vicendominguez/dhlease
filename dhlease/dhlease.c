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

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/queue.h>
#include "dhlease.h"

static FILE *fp;
static char *prog;
static int  token;	/* contains the current valid token */
static int  inblock;	/* indicates whether we are inside a lease block */

/* Program options */
static const char *opts = "haxf:i:m:c:vd";
static int  aflag;
static int  cflag;
static int  dflag;
static int  fflag;
static int  iflag;
static int  sflag;
static int  mflag;
static int  xflag;
static int  vflag;
static char *cval;
static char *mval;
static char *ival;

/* General purpose parser buffers */
static char buffer[2048];
static struct lease_t *lbuf;

/* Line and character position */
static int cpos;
static int line;


static const struct keywords {
        const char      *name;
        int             value;
} keywords[] = {
	      { "abandoned",		      TOK_ABANDONED },
        { "client-hostname",    TOK_CLIENT_HOSTNAME },
        { "ends",               TOK_ENDS },
        { "ethernet",           TOK_ETHERNET },
        { "hardware",           TOK_HARDWARE },
        { "lease",              TOK_LEASE },
        { "starts",             TOK_STARTS }
};


static void
usage(void)
{
        fprintf(stderr, "%s -- dhcp lease viewer\n", prog);
        fprintf(stderr, "  usage: %s [-haxvd] [-f file...] [-i ip_addr] [-c client] [-m mac_addr]\n", prog);
        fprintf(stderr, "   -h this help\n");
	fprintf(stderr, "   -d remove duplicate MAC-leases; show only most recent lease\n");
        fprintf(stderr, "   -c [client] search for client\n");
        fprintf(stderr, "   -i [ip_addr] search for ip address\n");
        fprintf(stderr, "   -m [mac_addr] search for mac address\n");
        fprintf(stderr, "   -f [file] path to dhcp lease file, defaults to %s\n", DEFAULT_LEASE_FILE);
        fprintf(stderr, "   -a show active leases, mutually exclusive with -x\n");
        fprintf(stderr, "   -x show expired leases, mutually exclusive with -a\n");
	fprintf(stderr, "   -v slightly more verbose\n");
        exit(EXIT_FAILURE);
}


static int
error(const char *fmt, ...)
{
	va_list	arglist;

	va_start(arglist, fmt);
	(void)vfprintf(stderr, fmt, arglist);
	va_end(arglist);

	exit(EXIT_FAILURE);
}


/*
 * Returns 0 if search is contained within src, otherwise 1
 */
static int
match_partial_string(const char *src, const char *search)
{
	if (src == NULL || search == NULL)
		return -1;

        if (strcasestr(src, search) == NULL)
                return -1;
        return 0;
}


/*
 * Converts a time_t to a string representation
 */
static char
*time_to_string(const time_t *tt)
{
	char *tbuf;
	struct tm tm;

	tbuf = (char *)malloc(128);
	strftime(tbuf, sizeof(tbuf), "%Y/%m%/%d %H:%M:%S", localtime_r(tt, &tm));

	return strtok(asctime_r(&tm, tbuf), "\n");
}


/*
 * Converts a textual representation of a date to a time_t
*/
static time_t
string_to_time(const char *datestr)
{
	char *err;
	struct tm tm;

	if ((err = strptime(datestr, "%Y/%m/%d %H:%M:%S", &tm)) == NULL)
		error("%s: time conversion failed: %s\n", prog, datestr);

	return mktime(&tm);
}


/*
 * Compares a time_t against NOW and return 1 or 0 if the time_t
 * is in the past or future, respectively.
 */
static int
has_lease_expired(const time_t tend)
{
	time_t tnow;

	tnow = time(NULL);
	if (difftime(tend, tnow) < 0.0f)
		return 1;
	return 0;
}


/*
 * Compares two time_t's and return an integer less than, equal to,
 * or greater than 0 depending on whether t2 is ahead, equal to,
 * or behind t1, respectively.
 */
static int compare_time(const time_t t1, const time_t t2)
{
	double diff = difftime(t1, t2);

	/* t2 is ahead of t1 */
	if (diff < 0.0f)
		return -1;

	/* t1 and t2 are identical */
	else if (diff == 0.0f)
		return 0;

	/* t2 is behind t1 */
	else
		return 1;
}


/*
 * Filter out any duplicate MAC entries so that only the newest lease
 * for a given MAC address is left in the list of leases. This method
 * works in quadratic time.
 */
static void remove_duplicates(void)
{
	struct lease_t *p_cur, *p_cur_sub;

	if (TAILQ_EMPTY(&head))
		return;

	TAILQ_FOREACH(p_cur, &head, entities) {
    if (p_cur->macaddr) {
		  TAILQ_FOREACH(p_cur_sub, &head, entities) {
        if (p_cur_sub->macaddr) {
			    if (strcasecmp(p_cur->macaddr, p_cur_sub->macaddr) == 0) {
				    if (compare_time(p_cur->end, p_cur_sub->end) == -1) {
					    TAILQ_REMOVE(&head, p_cur, entities);
				    }
			    }
        }
		  }
    }
    else {
      TAILQ_REMOVE(&head, p_cur, entities);
    }
	}
}


/*
 * Format, filter and show output
 */
static void
output_leases(const size_t cltlen, const size_t iplen, const size_t maclen, const size_t slen, const size_t elen)
{
	int display = 1;
	struct lease_t *p_cur;

	printf("%-*s%-*s%-*s%-*s%-*s%-*s\n",
		(int)cltlen + 2, "CLIENT",
		(int)iplen  + 2, "IP ADDRESS",
		(int)maclen + 2, "MAC ADDRESS",
                (int)slen   + 2, "LEASE START",
		(int)elen   + 2, "LEASE END",
		7           + 2, "EXPIRED");

	if (TAILQ_EMPTY(&head))
		return;

	TAILQ_FOREACH(p_cur, &head, entities) {
		/* Depending on options, find out whether to show the current lease entry */
		if (mflag)
			display = (match_partial_string(p_cur->macaddr, mval) == 0) ? 1 : 0;
		if (cflag)
			display = (match_partial_string(p_cur->client, cval) == 0) ? 1 : 0;
		if (iflag)
			display = (match_partial_string(p_cur->ipaddr, ival) == 0) ? 1 : 0;
		if (aflag)
			display = has_lease_expired(p_cur->end) ? 0 : 1;
		if (xflag)
			display = has_lease_expired(p_cur->end) ? 1 : 0;

		if (display == 1)
			printf("%-*s%-*s%-*s%-*s%-*s%-*s\n",
				(int)cltlen + 2, p_cur->client,
				(int)iplen  + 2, p_cur->ipaddr,
				(int)maclen + 2, p_cur->macaddr,
				(int)slen   + 2, time_to_string(&p_cur->start),
				(int)elen   + 2, time_to_string(&p_cur->end),
				7           + 2, has_lease_expired(p_cur->end) ? "Yes" : "No");
	}
}


/*
 * Initialize and perform parsing and handle parsing of tokens
 */
static void
parse_lease_file(void)
{
	int tmp;
	int count;
	int hastoken;
	size_t len_client;
	size_t len_ipaddr;
	size_t len_macaddr;
	size_t len_start;
	size_t len_end;

	cpos = 0;
	line = 0;
	token = 0;

	/* For padding in output_leases */
	len_client = 0;
	len_ipaddr = 0;
	len_macaddr = 0;
	len_start = 0;
	len_end = 0;

	/* No. of valid tokens encountered */
	count = 0;

	/* Do we have a valid token at the moment? */
	hastoken = 0;

	/* Are we inside a lease block? */
	inblock = 0;

	do {
		token = get_token(&count, &hastoken);

		/* We have just finished a block and found the closing curly brace */
		if (inblock == 0 && buffer[0] == CHAR_CURLY_BRACE_END)
			continue;

		if (count == 1 && hastoken == 1 && token != TOK_LEASE)
			error("%s: syntax error: expected a 'lease' section, got '%s'\n",
				prog, token, buffer);

		if (hastoken == 1 && token != TOK_LEASE && inblock == 0)
			error("%s: parse error: found token '%s' outside lease boundaries\n", prog, buffer);

		switch (token) {
			/* Get assigned IP address, ensure syntax */
			case TOK_LEASE:
				if (inblock == 1)
					error("%s: parse error: lease section began inside existing lease section\n", prog);
				inblock = 1;
				parse_ip_address();
				if (strlen(buffer) > len_ipaddr)
					len_ipaddr = strlen(buffer);
				seek_char(CHAR_CURLY_BRACE_START);
				asprintf(&lbuf->ipaddr, "%s", buffer);
				if (strlen(buffer) > len_ipaddr)
					len_ipaddr = strlen(buffer);
				break;

			/* Read and parse date string */
			case TOK_STARTS:
				check_block_scope();
				read_string_to_semicolon();
				lbuf->start = parse_date_string();
				if (strlen(time_to_string(&lbuf->start)) > len_start)
					len_start = strlen(time_to_string(&lbuf->start));
				break;

			/* Read and parse date string */
			case TOK_ENDS:
				check_block_scope();
				read_string_to_semicolon();
				lbuf->end = parse_date_string();
				if (strlen(time_to_string(&lbuf->end)) > len_end)
					len_end = strlen(time_to_string(&lbuf->end));
				break;

			/* Read and parse mac address string */
			case TOK_HARDWARE:
				check_block_scope();
				tmp = get_token(&count, &hastoken);
				if (tmp != TOK_ETHERNET)
					break;

				parse_ethernet_address();
				asprintf(&lbuf->macaddr, "%s", buffer);
				if (strlen(buffer) > len_macaddr)
					len_macaddr = strlen(buffer);
				break;
			/* Read and format client name string */
			case TOK_CLIENT_HOSTNAME:
				check_block_scope();
				parse_client_hostname();
				asprintf(&lbuf->client, "%s", buffer);
				if (strlen(buffer) > len_client)
					len_client = strlen(buffer);
				break;

			/* Check if the lease is abandoned */
			case TOK_ABANDONED:
				tmp = peek_char();
// not working tmp is always \x10 insted of ;
//				if (tmp != CHAR_SEMICOLON)
//					error("%s: parse error: expected ';' after '%s'\n", prog, buffer);
				lbuf->abandoned = 1;
			default:
				;
		}
	} while (!feof(fp));

	fclose(fp);

	if (dflag)
		remove_duplicates();
	output_leases(len_client, len_ipaddr, len_macaddr, len_start, len_end);
}


static void
check_block_scope(void)
{
	if (!inblock)
		error("%s: parse error: element '%s' found outside block scope\n", prog, buffer);
}


/*
 * Jump to the desired character in the same line.
 * The character must be found or the parsing run will fail
 */
static void
seek_char(const unsigned char chr)
{
	int c, located;
	located = 0;
	do {
		c = get_char();
		if (c == chr) {
			located = 1;
			return;
		}

		if (c == '\n' && located == 0)
			error("%s: parse error: missing '%c' in line %d\n", prog, chr, line);
	} while(1);
}


/*
 * Take a look at the next character in the byte stream without
 * advancing the pointer
 */
static int
peek_char(void)
{
	int c, d;

	c = getc(fp);
	if (feof(fp))
		return -1;

	d = ungetc(c, fp);
	if (feof(fp))
		error("%s: can't peek ahead\n", prog);

	return d;
}


/*
 * Get the next byte from the file stream.  Includes some
 * minor parser/list logic.
 */
static int
get_char(void)
{
	int c;


	c = getc(fp);

	if (feof(fp))
		return -1;

	if (ferror(fp) != 0)
		error("%s: failed to read from lease file\n", prog);

	/*
		The inblock is not set by the matching '{' but rather as soon as the
		"lease" token is encountered. There is still syntax checking for the
		'{', though.
	*/
	if (c == '}' && inblock != 1)
		error("%s: parse error: unbalanced bracket at line %d, pos %d\n", prog, line, cpos);

	if (c == '}') {
		inblock = 0;
		TAILQ_INSERT_TAIL(&head, lbuf, entities);
	}

	if (c == '\n') {
		line++;
		cpos = 0;
	}
	cpos++;

	return c;

}


/*
 * Jump forward to the next occurrence of ';'
 */
static void
read_string_to_semicolon(void)
{
	int c, i;
	memset(buffer, 0, sizeof(buffer));

	i = 0;
	do {
		c = get_char();
		if (c == -1)
			error("%s: parse error: unexpected EOF at line %d, pos %d\n", prog, line, cpos);

		if (c == '\n')
			error("%s: parse error: unexpected newline at line %d, pos %d, expected ';'\n", prog, line, cpos);

		if (c == ';')
			break;

		buffer[i++] = c;

	} while (1);
}


static void
parse_ip_address(void)
{
	int c, i;
	memset(buffer, 0, sizeof(buffer));

	i = 0;
	do {
		c = get_char();
		if (c == -1)
			error("%s: parse error: unexpected EOF at line %d, pos %d\n", prog, line, cpos);

		if (c == '\n')
			error("%s: parse error: unexpected newline at line %d, pos %d\n", prog, line, cpos);

		if (isspace(c) || c == '"' || c == ';')
			break;

		if (isascii(c) || isdigit(c))
			buffer[i++] = c;
	} while(1);

}


static void
parse_ethernet_address(void)
{
	int c, i;
	memset(buffer, 0, sizeof(buffer));

	i = 0;
	do {
		c = get_char();

		if (c == -1)
			error("%s: parse error: unexpected EOF at line %d, pos %d\n", prog, line, cpos);

		if (c == '\n')
			error("%s: parse error: unexpected newline at line %d, pos %d\n", prog, line, cpos);

		if (isspace(c) || c == '"' || c == ';')
			break;

		if (isascii(c) || isdigit(c))
			buffer[i++] = c;
	} while(1);
}


/*
 * Parse the client hostname, stripping the surrounding quotes
 * in the process
 */
static void
parse_client_hostname(void)
{
	int c, i;
	memset(buffer, 0, sizeof(buffer));

	i = 0;
	do {
		c = get_char();

		if (c == -1)
			error("%s: parse error: unexpected EOF at line %d, pos %d\n", prog, line, cpos);

		if (c == '\n')
			error("%s: parse error: unexpected newline at line %d, pos %d\n", prog, line, cpos);

		if (c == '"')
			continue;

		if (isspace(c) || c == ';')
			break;

		if (isascii(c) || isdigit(c))
			buffer[i++] = c;
	} while(1);
}


/*
 * Parse the date string and immediately get rid of the prepended
 * weekday which we don't need
 */
static time_t
parse_date_string(void)
{
	char datebuf[64];
	if (strlen(buffer) < 3)
		error("%s: weird buffer\n", prog);

	/* For a specific byte sequence, wipe the 2 first chars from the buffer */
	if (isdigit(buffer[0]) && isspace(buffer[1]))
		strncpy(datebuf, buffer + 2, strlen(buffer) - 2);

	return string_to_time(datebuf);
}


/*
 * Look for the next token by scanning bytes until we reach a boundary
 * and then check if the string is a valid (supported) token
 */
static int
get_token(int *count, int *found)
{
	int i, c, kwl;

	i = kwl = 0;

	memset(buffer, 0, sizeof(buffer));

	/* Haven't found a token yet */
	*found = 0;
	do {
		c = get_char();
		if (c == -1)
			return 0;

		if (c == -1) {
			printf("eof reached\n");
			break;
		}

		if (c == '\t' || c == '\n' || c == ';' || isspace(c))
			break;

		buffer[i++] = c;

		if (c == '#') {
			printf("comment char found! ");
			do {
				c = get_char();
			}
			while (c != '\n');
			printf ("eol!\n");
			continue;
		}

	}
	while (1);

	/* Check if we have a token */
	kwl = lookup(buffer);
	if (kwl <= TOK_INVALID_TOKEN)
		return TOK_INVALID_TOKEN;

	/* For lease tokens, allocate a new structure for the current lease */
	if (kwl == TOK_LEASE)
		lbuf = calloc(1, sizeof(struct lease_t));

	*count += 1;
	*found = 1;

	return kwl;
}


static void
open_lease_file(const char *filename)
{
	if ((fp = fopen(filename, "r")) == NULL)
		error("%s: couldn't open lease file %s\n", prog, filename);
}



static int
keyword_cmp(const void *p1, const void *p2)
{
	return (strcasecmp(p1, ((const struct keywords *)p2)->name));
}


static int
lookup(char *value)
{
	const struct keywords *p;

	p = bsearch(value, keywords, sizeof(keywords) / sizeof(keywords[0]),
		sizeof(keywords[0]), keyword_cmp);

	if (p)
		return (p->value);
	return TOK_INVALID_TOKEN;
}


int
main(int argc, char **argv)
{
	int g;
        char *tmp;
	char *fval;

	TAILQ_INIT(&head);

        if ((tmp = strrchr(argv[0], '/')) != NULL)
                prog = tmp + 1;
	else
		prog = argv[0];

	while ((g = getopt(argc, argv, opts)) != -1) {
		switch (g) {
			case 'a':
				aflag = 1;
				break;
			case 'd':
				dflag = 1;
				break;
			case 'f':
				fflag = 1;
				asprintf(&fval, "%s", optarg);
				break;
			case 'm':
				mflag = 1;
				asprintf(&mval, "%s", optarg);
				break;
			case 'i':
				iflag = 1;
				asprintf(&ival, "%s", optarg);
				break;
			case 'c':
				cflag = 1;
				asprintf(&cval, "%s", optarg);
				break;
			case 's':
				sflag  = 1;
				break;
			case 'x':
				xflag = 1;
				break;
			case 'v':
				vflag = 1;
				break;
			case 'h':
				/* FALLTHROUGH */
			case '?':
				/* FALLTHROUGH */
			default:
				usage();
		}
	}

	if (aflag && xflag)
		error("%s: the -a and -x flags are mutually exclusive\n", prog);

	if (!fflag)
		asprintf(&fval, "%s", DEFAULT_LEASE_FILE);

	if (vflag)
		printf("using lease file: %s\n", fval);


	open_lease_file(fval);
	parse_lease_file();

	return 0;
}
