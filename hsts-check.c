/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Contributor:
 * - Aaron Meihm ameihm@mozilla.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#define __USE_GNU
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

#define CIPHER_LIST "HIGH:!aNULL:!eNULL:!PSK:!DES:!SRP:!MD5:!RC4:!EXPORT"
#define MAX_HTTP_RESPONSE 10240

struct checkhost {
	char			hostname[1024];
	int			err;
	char			errstr[1024];
	struct checkhost	*next;
	char			proof[1024];
	int			found;
};

struct checkhost *hostlist = NULL;

int		check_host(struct checkhost *);
void		check_hosts(void);
void		find_header(struct checkhost *, char *);
int		check_header(struct checkhost *, char *);
void		load_hostlist(char *);
void		results(void);
void		usage(void);

void
check_hosts()
{
	struct checkhost *h = hostlist;

	if (h == NULL)
		return;

	for (;;) {
		check_host(h);
		if (h->next == NULL)
			break;
		h = h->next;
	}
}

void
check_error(struct checkhost *h, char *fmt, ...)
{
	va_list ap;
	h->err = 1;

	if (fmt == NULL) {
		strncpy(h->errstr, "unknown error", sizeof(h->errstr) - 1);
		return;
	}

	va_start(ap, fmt);
	vsnprintf(h->errstr, sizeof(h->errstr), fmt, ap);
	va_end(ap);
}

int
check_host(struct checkhost *h)
{
	char iobuf[4096];
	char respbuf[MAX_HTTP_RESPONSE];
	SSL_CTX *ctx;
	const SSL_METHOD *method = SSLv23_method();
	int flags = SSL_OP_NO_SSLv2;
	BIO *b;
	SSL *s;
	int ret;

	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		check_error(h, NULL);
		return (-1);
	}
	SSL_CTX_set_options(ctx, flags);

	b = BIO_new_ssl_connect(ctx);
	if (b == NULL) {
		check_error(h, NULL);
		return (-1);
	}
	snprintf(iobuf, sizeof(iobuf), "%s:443", h->hostname);
	BIO_set_conn_hostname(b, iobuf);

	BIO_get_ssl(b, &s);
	if (SSL_set_cipher_list(s, CIPHER_LIST) == 0) {
		check_error(h, NULL);
		return (-1);
	}

	if (BIO_do_connect(b) != 1) {
		check_error(h, "connection could not be established");
		return (-1);
	}

	if (BIO_do_handshake(b) != 1) {
		check_error(h, "ssl/tls handshake failed");
		return (-1);
	}

	snprintf(iobuf, sizeof(iobuf), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", h->hostname);
	BIO_puts(b, iobuf);
	memset(respbuf, 0, sizeof(respbuf));
	ret = BIO_read(b, respbuf, sizeof(respbuf) - 1);
	if (ret <= 0) {
		check_error(h, "no data returned from server");
		return (-1);
	}
	find_header(h, respbuf);

	return (0);
}

void
find_header(struct checkhost *h, char *respbuf)
{
	char linebuf[2048];
	char *p0, *p1;
	int lb = 0;

	p0 = linebuf;
	memset(linebuf, 0, sizeof(linebuf));
	p1 = respbuf;
	for (;;) {
		if (*p1 == '\0')
			break;

		if (*p1 == '\r') {
			p1++;
			continue;
		}

		if (*p1 == '\n') {
			if (lb == 1) {
				// Done with headers
				return;
			}
			lb = 1;
			if (check_header(h, linebuf))
				return;
			p0 = linebuf;
			memset(linebuf, 0, sizeof(linebuf));
		} else {
			lb = 0;
			if ((strlen(linebuf) + 1) < sizeof(linebuf))
				*(p0++) = *p1;
		}
		p1++;
	}
}

int
check_header(struct checkhost *h, char *ln)
{
	char match[] = "Strict-Transport-Security:";

	if (strncasecmp(match, ln, strlen(match)) != 0)
		return (0);
	h->found = 1;
	strncpy(h->proof, ln, sizeof(h->proof) - 1);
	return (1);
}

void
load_hostlist(char *hpath)
{
	char buf[1024];
	FILE *f;

	f = fopen(hpath, "r");
	if (f == NULL) {
		perror("fopen");
		exit(-1);
	}
	while (fgets(buf, sizeof(buf), f) != NULL) {
		struct checkhost *new;
		char *p0;

		for (p0 = buf; *p0 != '\0'; p0++) {
			if ((*p0 == '\n') || (*p0 == '\r')) {
				*p0 = '\0';
				break;
			}
		}

		new = malloc(sizeof(struct checkhost));
		if (new == NULL) {
			perror("malloc");
			exit(-1);
		}
		memset(new->hostname, 0, sizeof(new->hostname));
		strncpy(new->hostname, buf, sizeof(new->hostname) - 1);
		new->next = NULL;
		new->err = 0;
		memset(new->errstr, 0, sizeof(new->errstr));
		memset(new->proof, 0, sizeof(new->proof));
		new->found = 0;

		if (hostlist == NULL)
			hostlist = new;
		else {
			struct checkhost *last;
			for (last = hostlist; last->next != NULL; last = last->next);
			last->next = new;
		}
	}
	if (fclose(f) != 0) {
		perror("fclose");
		exit(-1);
	}
}

void
results()
{
	struct checkhost *p0;

	if (hostlist == NULL)
		return;

	p0 = hostlist;
	for (;;) {
		printf("%s %d", p0->hostname, p0->found);
		if (p0->found) {
			printf(" hsts [%s]\n", p0->proof);
		} else if (p0->err) {
			printf(" error [%s]\n", p0->errstr);
		} else {
			printf(" none []\n");
		}
		if (p0->next == NULL)
			break;
		p0 = p0->next;
	}
}

void
usage()
{
	fprintf(stderr, "usage: hsts-check [-h] hostlist_file\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *hpath;
	char ch;

	SSL_library_init();
	SSL_load_error_strings();

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	hpath = argv[0];

	load_hostlist(hpath);
	check_hosts();
	results();

	return (0);
}
