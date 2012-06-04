/* Small check program to see what remote peers are presenting
 * you as x509 chain. Beware, dirty code!
 *
 * (C) 2008-2012 Sebastian Krahmer, under the GPL.
 *
 * c++ x509show.cc -lssl -lcrypto
 *
 */
#include <stdio.h>
#include <string>
#include <cerrno>
extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}
#include <cstdio>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


using namespace std;

static int depth = 0;

vector<X509 *> certs;

int verify_callback(int ok, X509_STORE_CTX *store)
{
	X509 *x509 = X509_STORE_CTX_get_current_cert(store);

	if (!x509) {
		fprintf(stderr, "Error: No x509 in store?!\n");
		return -1;
	}

	certs.push_back(X509_dup(x509));

	string prefix = "                                                                   ";
	++depth;
	prefix = prefix.substr(0, depth);
	if (depth > 1)
		printf("%s|       ||", prefix.c_str());
	else
		printf(" |");
	printf("\n%s \\---- Issuer: [", prefix.c_str()); X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(x509), 0, XN_FLAG_ONELINE);
	printf("]\n%s |   \\ Subject: [", prefix.c_str()); X509_NAME_print_ex_fp(stdout, X509_get_subject_name(x509), 0, XN_FLAG_ONELINE);
	printf("] (%s)\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(store)));
	return ok;
}



int do_SSL(int fd)
{
	SSL_CTX *ssl_ctx = NULL;
#ifdef STUPID_OLD_OPENSSL
	SSL_METHOD *method = NULL;
#else
	const SSL_METHOD *method = NULL;
#endif
	SSL *ssl = NULL;
	X509 *x509 = NULL;


	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	if ((method = TLSv1_client_method()) == NULL) {
		fprintf(stderr, "TLSv1_client_method\n");
		return -1;
	}

	if ((ssl_ctx = SSL_CTX_new(method)) == NULL) {
		fprintf(stderr, "SSL_CTX_new %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (SSL_CTX_load_verify_locations(ssl_ctx, NULL, "/etc/ssl/certs") != 1) {
		fprintf(stderr, "SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
		fprintf(stderr, "SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

	SSL_CTX_set_verify(ssl_ctx,
	                   SSL_VERIFY_PEER|
	                   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
	                   verify_callback);
	SSL_CTX_set_verify_depth(ssl_ctx, 1000);
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);

	if (SSL_CTX_set_cipher_list(ssl_ctx, CIPHER_LIST) != 1) {
		fprintf(stderr, "SSL_CTX_set_cipher_list: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if ((ssl = SSL_new(ssl_ctx)) == NULL)
		return -1;
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) <= 0) {
		fprintf(stderr, "SSL_connect failed\n");
		return -1;
	}


	if ((x509 = SSL_get_peer_certificate(ssl)) == NULL) {
		fprintf(stderr, "No cert!\n");
		return -1;
	}

	printf("\n\n\n");


	int err;
	if ((err = SSL_get_verify_result(ssl)) != X509_V_OK) {
		fprintf(stderr, "%s\n", X509_verify_cert_error_string(err));
		return -1;
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);
	return 0;
}


void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


int tcp_connect(const char *host, u_short port = 443)
{
	int sock = -1, r = -1;
	char service[20];
	struct addrinfo *res = NULL, hints = {0, AF_UNSPEC, SOCK_STREAM, 0};

	sprintf(service, "%d", port);
	if ((r = getaddrinfo(host, service, &hints, &res)) != 0) {
		fprintf(stderr, "tcp_connect::getaddrinfo: %s\n", gai_strerror(r));
		exit(EXIT_FAILURE);
	}

	if ((sock = socket(res->ai_family, SOCK_STREAM, 0)) < 0)
		die("sock");

	if (connect(sock, res->ai_addr, res->ai_addrlen) < 0)
		die("connect");

	freeaddrinfo(res);
	return sock;
}


int main(int argc, char **argv)
{
	if (argc < 2) {
		printf("\nUsage: %s <IP or hostname>|less\n\n", argv[0]);
		return 1;
	}

	int fd = tcp_connect(argv[1], 443);
	printf("\noverall result: %d\nHuman readable X509 chain follows:\n\n", do_SSL(fd));


	close(fd);
	for (vector<X509 *>::iterator i = certs.begin(); i != certs.end(); ++i) {
		X509_print_ex_fp(stdout, *i, 0, XN_FLAG_MULTILINE);
		X509_free(*i);
	}
	printf("\n");

	return 0;
}


