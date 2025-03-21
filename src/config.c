/*
 *  Copyright (c) 2015 Adrien Vergé
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give permission
 *  to link the code of portions of this program with the OpenSSL library under
 *  certain conditions as described in each individual source file, and
 *  distribute linked combinations including the two.
 *  You must obey the GNU General Public License in all respects for all of the
 *  code used other than OpenSSL.  If you modify file(s) with this exception,
 *  you may extend this exception to your version of the file(s), but you are
 *  not obligated to do so.  If you do not wish to do so, delete this exception
 *  statement from your version.  If you delete this exception statement from
 *  all source files in the program, then also delete it here.
 */

#include "config.h"
#include "log.h"

#include <openssl/x509.h>  /* work around OpenSSL bug: missing definition of STACK_OF */
#include <openssl/tls1.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const struct vpn_config invalid_cfg = {
	.gateway_host = {'\0'},
	.gateway_port = 0,
	.username = {'\0'},
	.password = {'\0'},
	.password_set = 0,
	.cookie = NULL,
	.saml_port = 0,
	.saml_session_id = {'\0'},
	.otp = {'\0'},
	.otp_prompt = NULL,
	.otp_delay = -1,
	.no_ftm_push = -1,
	.pinentry = NULL,
	.realm = {'\0'},
	.iface_name = {'\0'},
	.sni = {'\0'},
	.set_routes = -1,
	.routes = NULL,
	.set_dns = -1,
	.dns = NULL,
	.domain_suffix = {'\0'},
	.pppd_use_peerdns = -1,
#if HAVE_RESOLVCONF
	.use_resolvconf = -1,
#endif
	.use_syslog = -1,
	.half_internet_routes = -1,
	.persistent = -1,
#if HAVE_USR_SBIN_PPPD
	.pppd_log = NULL,
	.pppd_plugin = NULL,
	.pppd_ipparam = NULL,
	.pppd_ifname = NULL,
	.pppd_call = NULL,
	.pppd_accept_remote = -1,
#endif
#if HAVE_USR_SBIN_PPP
	.ppp_system = NULL,
#endif
	.ca_file = NULL,
	.user_cert = NULL,
	.user_key = NULL,
	.pem_passphrase = {'\0'},
	.pem_passphrase_set = 0,
	.insecure_ssl = -1,
	.cipher_list = NULL,
	.min_tls = -1,
	.seclevel_1 = -1,
	.cert_whitelist = NULL,
	.use_engine = -1,
	.user_agent = NULL,
	.hostcheck = NULL,
	.check_virtual_desktop = NULL,
};

/*
 * Adds a sha256 digest to the list of trusted certificates.
 */
int add_trusted_cert(struct vpn_config *cfg, const char *digest)
{
	struct x509_digest *new;

	new = malloc(sizeof(struct x509_digest));
	if (new == NULL)
		return ERR_CFG_NO_MEM;

	new->next = NULL;
	strncpy(new->data, digest, SHA256STRLEN - 1);
	new->data[SHA256STRLEN - 1] = '\0';

	if (cfg->cert_whitelist == NULL) {
		cfg->cert_whitelist = new;
	} else {
		struct x509_digest *last;

		for (last = cfg->cert_whitelist;
		     last->next != NULL;
		     last = last->next)
			;
		last->next = new;
	}

	return 0;
}

/*
 * Converts string to bool int
 *
 * @params[in] str  the string to read from
 * @return          0 or 1 if successful, < 0 if unrecognized value
 */
int strtob(const char *str)
{
	if (str[0] == '\0')
		return 0;
	else if (strcasecmp(str, "true") == 0)
		return 1;
	else if (strcasecmp(str, "false") == 0)
		return 0;
	else if (isdigit(str[0]) == 0)
		return -1;

	long i = strtol(str, NULL, 0);

	if (i < 0 || i > 1)
		return -1;
	return i;
}

/*
 * Converts string to TLS version
 *
 * @params[in] str  the string to read from
 * @return          OpenSSL version or -1
 */
int parse_min_tls(const char *str)
{
	if (str[0] != '1' || str[1] != '.' || str[2] == 0 || str[3] != 0)
		return -1;
	switch (str[2]) {
#ifdef TLS1_VERSION
	case '0':
		return TLS1_VERSION;
#endif
#ifdef TLS1_1_VERSION
	case '1':
		return TLS1_1_VERSION;
#endif
#ifdef TLS1_2_VERSION
	case '2':
		return TLS1_2_VERSION;
#endif
#ifdef TLS1_3_VERSION
	case '3':
		return TLS1_3_VERSION;
#endif
	default:
		return -1;
	}
}

/*
 * Reads filename contents and fill cfg with its values.
 *
 * @param[out] cfg       the struct vpn_config to store configuration values
 * @param[in]  filename  the file to read values from
 * @return               0 if successful, or < 0 in case of error
 */
int load_config(struct vpn_config *cfg, const char *filename)
{
	int ret = 0;
	FILE *file;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	file = fopen(filename, "r");
	if (file == NULL) {
		ret = ERR_CFG_SEE_ERRNO;
		goto err_return;
	}

	// Read line by line
	while ((read = getline(&line, &len, file)) != -1) {
		char *key, *equals, *val;

		// Ignore blank lines. We could argue that the string must be at least
		// 3 chars to be valid, eg. 'x=\n' but let the rest of the function
		// logic handle that. NOTE: getline includes the '\n' in the string,
		// which is removed later on.
		if (read < 2)
			continue;

		if (line[0] == '#')
			continue;

		// Expect something like: "key = value"
		equals = strchr(line, '=');
		if (equals == NULL) {
			log_warn("Bad line in configuration file: \"%s\".\n", line);
			continue;
		}
		equals[0] = '\0';
		key = line;
		val = equals + 1;

		// Remove heading spaces
		while (isspace(key[0]))
			key++;
		while (isspace(val[0]))
			val++;
		// Remove trailing spaces
		for (int i = strlen(key) - 1; i > 0; i--) {
			if (isspace(key[i]))
				key[i] = '\0';
			else
				break;
		}
		for (int i = strlen(val) - 1; i > 0; i--) {
			if (isspace(val[i]))
				val[i] = '\0';
			else
				break;
		}

		if (strcmp(key, "host") == 0) {
			strncpy(cfg->gateway_host, val, GATEWAY_HOST_SIZE);
			cfg->gateway_host[GATEWAY_HOST_SIZE] = '\0';
		} else if (strcmp(key, "port") == 0) {
			long port = strtol(val, NULL, 0);

			if (port < 1 || port > 65535) {
				log_warn("Bad port in configuration file: \"%ld\".\n",
				         port);
				continue;
			}
			cfg->gateway_port = (uint16_t)port;
		} else if (strcmp(key, "username") == 0) {
			strncpy(cfg->username, val, USERNAME_SIZE);
			cfg->username[USERNAME_SIZE] = '\0';
		} else if (strcmp(key, "password") == 0) {
			strncpy(cfg->password, val, PASSWORD_SIZE);
			cfg->password[PASSWORD_SIZE] = '\0';
			cfg->password_set = 1;
		} else if (strcmp(key, "otp") == 0) {
			strncpy(cfg->otp, val, OTP_SIZE);
			cfg->otp[OTP_SIZE] = '\0';
		} else if (strcmp(key, "otp-prompt") == 0) {
			free(cfg->otp_prompt);
			cfg->otp_prompt = strdup(val);
		} else if (strcmp(key, "otp-delay") == 0) {
			long otp_delay = strtol(val, NULL, 0);

			if (otp_delay < 0 || otp_delay > UINT_MAX) {
				log_warn("Bad value for otp-delay in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->otp_delay = otp_delay;
		} else if (strcmp(key, "cookie") == 0) {
			log_warn("Ignoring option \"%s\" in the config file.\n", key);
		} else if (strcmp(key, "cookie-on-stdin") == 0) {
			log_warn("Ignoring option \"%s\" in the config file.\n", key);
		} else if (strcmp(key, "no-ftm-push") == 0) {
			int no_ftm_push = strtob(val);

			if (no_ftm_push < 0) {
				log_warn("Bad no-ftm-push in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->no_ftm_push = no_ftm_push;
		} else if (strcmp(key, "pinentry") == 0) {
			free(cfg->pinentry);
			cfg->pinentry = strdup(val);
		} else if (strcmp(key, "realm") == 0) {
			strncpy(cfg->realm, val, REALM_SIZE);
			cfg->realm[REALM_SIZE] = '\0';
		} else if (strcmp(key, "set-dns") == 0) {
			int set_dns = strtob(val);

			if (set_dns < 0) {
				log_warn("Bad set-dns in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->set_dns = set_dns;
		} else if (strcmp(key, "sni") == 0) {
			strncpy(cfg->sni, val, GATEWAY_HOST_SIZE);
			cfg->sni[GATEWAY_HOST_SIZE] = '\0';
		} else if (strcmp(key, "set-routes") == 0) {
			int set_routes = strtob(val);

			if (set_routes < 0) {
				log_warn("Bad set-routes in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->set_routes = set_routes;
		} else if (strcmp(key, "half-internet-routes") == 0) {
			int half_internet_routes = strtob(val);

			if (half_internet_routes < 0) {
				log_warn("Bad half-internet-routes in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->half_internet_routes = half_internet_routes;
		} else if (strcmp(key, "persistent") == 0) {
			unsigned long persistent = strtoul(val, NULL, 0);

			if (persistent > UINT_MAX) {
				log_warn("Bad value for persistent in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->persistent = persistent;
#if HAVE_USR_SBIN_PPPD
		} else if (strcmp(key, "pppd-use-peerdns") == 0) {
			int pppd_use_peerdns = strtob(val);

			if (pppd_use_peerdns < 0) {
				log_warn("Bad pppd-use-peerdns in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->pppd_use_peerdns = pppd_use_peerdns;
		} else if (strcmp(key, "pppd-log") == 0) {
			free(cfg->pppd_log);
			cfg->pppd_log = strdup(val);
		} else if (strcmp(key, "pppd-plugin") == 0) {
			free(cfg->pppd_plugin);
			cfg->pppd_plugin = strdup(val);
		} else if (strcmp(key, "pppd-ipparam") == 0) {
			free(cfg->pppd_ipparam);
			cfg->pppd_ipparam = strdup(val);
		} else if (strcmp(key, "pppd-ifname") == 0) {
			free(cfg->pppd_ifname);
			cfg->pppd_ifname = strdup(val);
		} else if (strcmp(key, "pppd-call") == 0) {
			free(cfg->pppd_call);
			cfg->pppd_call = strdup(val);
		} else if (strcmp(key, "pppd-accept-remote") == 0) {
			int pppd_accept_remote = strtob(val);

			if (pppd_accept_remote < 0) {
				log_warn("Bad pppd-accept-remote in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->pppd_accept_remote = pppd_accept_remote;
#else
		} else if (strcmp(key, "pppd") == 0) {
			log_warn("Ignoring pppd option \"%s\" in the config file.\n",
			         key);
#endif
		} else if (strcmp(key, "ppp-system") == 0) {
#if HAVE_USR_SBIN_PPP
			cfg->ppp_system = strdup(val);
#else
			log_warn("Ignoring option \"%s\" in the config file.\n",
			         key);
#endif
		} else if (strcmp(key, "use-resolvconf") == 0) {
#if HAVE_RESOLVCONF
			int use_resolvconf = strtob(val);

			if (use_resolvconf < 0) {
				log_warn("Bad value for use-resolvconf in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->use_resolvconf = use_resolvconf;
#else
			log_warn("Ignoring option \"%s\" in the config file.\n",
			         key);
#endif
		} else if (strcmp(key, "use-syslog") == 0) {
			int use_syslog = strtob(val);

			if (use_syslog < 0) {
				log_warn("Bad use-syslog in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->use_syslog = use_syslog;
		} else if (strcmp(key, "trusted-cert") == 0) {
			if (strlen(val) != SHA256STRLEN - 1) {
				log_warn("Bad certificate sha256 digest in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			if (add_trusted_cert(cfg, val))
				log_warn("Could not add certificate digest to whitelist.\n");

		} else if (strcmp(key, "ca-file") == 0) {
			free(cfg->ca_file);
			cfg->ca_file = strdup(val);
		} else if (strcmp(key, "user-cert") == 0) {
			free(cfg->user_cert);
			cfg->user_cert = strdup(val);
			if (strncmp(cfg->user_cert, "pkcs11:", 7) == 0)
				cfg->use_engine = 1;
		} else if (strcmp(key, "dns") == 0) {
			free(cfg->domain_suffix);
			cfg->domain_suffix = val;
			continue;
		} else if (strcmp(key, "dns") == 0) {
			Node *newNode = (Node *)malloc(sizeof(Node));
			newNode->value = val;
			newNode->next = cfg->dns;
			cfg->dns = newNode;
			continue;
		} else if (strcmp(key, "route") == 0) {			
    		Node *newNode = (Node *)malloc(sizeof(Node));
			newNode->value = cidr_to_ip_mask(val);
			newNode->next = cfg->routes;
			cfg->routes = newNode;
			continue;
		} else if (strcmp(key, "saml-login") == 0) {
			long port = strtol(val, NULL, 0);

			if (port < 1 || port > 65535) {
				log_error("Bad SAML listen port: \"%s\".\n", val);
				goto err_free;
			}
			cfg->saml_port = (uint16_t)port;
		} else if (strcmp(key, "user-key") == 0) {
			free(cfg->user_key);
			cfg->user_key = strdup(val);
		} else if (strcmp(key, "pem-passphrase") == 0) {
			strncpy(cfg->pem_passphrase, val, PEM_PASSPHRASE_SIZE);
			cfg->pem_passphrase[PEM_PASSPHRASE_SIZE] = '\0';
			cfg->pem_passphrase_set = 1;
		} else if (strcmp(key, "insecure-ssl") == 0) {
			int insecure_ssl = strtob(val);

			if (insecure_ssl < 0) {
				log_warn("Bad insecure-ssl in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->insecure_ssl = insecure_ssl;
		} else if (strcmp(key, "cipher-list") == 0) {
			free(cfg->cipher_list);
			cfg->cipher_list = strdup(val);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		} else if (strcmp(key, "min-tls") == 0) {
			int min_tls = parse_min_tls(val);

			if (min_tls == -1) {
				log_warn("Bad min-tls in configuration file: \"%s\".\n",
				         val);
				continue;
			} else {
				cfg->min_tls = min_tls;
			}
#endif
		} else if (strcmp(key, "seclevel-1") == 0) {
			int seclevel_1 = strtob(val);

			if (seclevel_1 < 0) {
				log_warn("Bad seclevel-1 in configuration file: \"%s\".\n",
				         val);
				continue;
			}
			cfg->seclevel_1 = seclevel_1;
		} else if (strcmp(key, "user-agent") == 0) {
			free(cfg->user_agent);
			cfg->user_agent = strdup(val);
		} else if (strcmp(key, "hostcheck") == 0) {
			free(cfg->hostcheck);
			cfg->hostcheck = strdup(val);
		} else if (strcmp(key, "check-virtual-desktop") == 0) {
			free(cfg->check_virtual_desktop);
			cfg->check_virtual_desktop = strdup(val);
		} else {
			log_warn("Bad key in configuration file: \"%s\".\n", key);
			goto err_free;
		}
	}
	if (ferror(file))
		ret = ERR_CFG_SEE_ERRNO;

err_free:
	free(line);
	if (fclose(file))
		log_warn("Could not close %s (%s).\n", filename, strerror(errno));
err_return:
	return ret;
}

void destroy_vpn_config(struct vpn_config *cfg)
{
	free(cfg->otp_prompt);
	free(cfg->pinentry);
	free(cfg->cookie);
#if HAVE_USR_SBIN_PPPD
	free(cfg->pppd_log);
	free(cfg->pppd_plugin);
	free(cfg->pppd_ipparam);
	free(cfg->pppd_ifname);
	free(cfg->pppd_call);
#endif
#if HAVE_USR_SBIN_PPP
	free(cfg->ppp_system);
#endif
	free(cfg->ca_file);
	free(cfg->user_cert);
	free(cfg->user_key);
	free(cfg->cipher_list);
	free(cfg->user_agent);
	free(cfg->hostcheck);
	free(cfg->check_virtual_desktop);
	while (cfg->cert_whitelist != NULL) {
		struct x509_digest *tmp = cfg->cert_whitelist->next;

		free(cfg->cert_whitelist);
		cfg->cert_whitelist = tmp;
	}
}

void merge_config(struct vpn_config *dst, struct vpn_config *src)
{
	if (src->gateway_host[0])
		strcpy(dst->gateway_host, src->gateway_host);
	if (src->gateway_port != invalid_cfg.gateway_port)
		dst->gateway_port = src->gateway_port;
	if (src->username[0])
		strcpy(dst->username, src->username);
	if (src->password_set) {
		strcpy(dst->password, src->password);
		dst->password_set = src->password_set;
	}
	if (src->otp[0])
		strcpy(dst->otp, src->otp);
	if (src->otp_delay != invalid_cfg.otp_delay)
		dst->otp_delay = src->otp_delay;
	if (src->no_ftm_push != invalid_cfg.no_ftm_push)
		dst->no_ftm_push = src->no_ftm_push;
	if (src->cookie != invalid_cfg.cookie) {
		free(dst->cookie);
		dst->cookie = src->cookie;
	}
	if(src->saml_port != 0) {
		dst->saml_port = src->saml_port;
	}
	if (src->pinentry) {
		free(dst->pinentry);
		dst->pinentry = src->pinentry;
	}
	if (src->realm[0])
		strcpy(dst->realm, src->realm);
	if (src->iface_name[0])
		strcpy(dst->iface_name, src->iface_name);
	if (src->sni[0])
		strcpy(dst->sni, src->sni);
	if (src->set_routes != invalid_cfg.set_routes)
		dst->set_routes = src->set_routes;
	if (src->set_dns != invalid_cfg.set_dns)
		dst->set_dns = src->set_dns;
	if (src->pppd_use_peerdns != invalid_cfg.pppd_use_peerdns)
		dst->pppd_use_peerdns = src->pppd_use_peerdns;
#if HAVE_RESOLVCONF
	if (src->use_resolvconf != invalid_cfg.use_resolvconf)
		dst->use_resolvconf = src->use_resolvconf;
#endif
	if (src->use_syslog != invalid_cfg.use_syslog)
		dst->use_syslog = src->use_syslog;
	if (src->half_internet_routes != invalid_cfg.half_internet_routes)
		dst->half_internet_routes = src->half_internet_routes;
	if (src->persistent != invalid_cfg.persistent)
		dst->persistent = src->persistent;
#if HAVE_USR_SBIN_PPPD
	if (src->pppd_log) {
		free(dst->pppd_log);
		dst->pppd_log = src->pppd_log;
	}
	if (src->pppd_plugin) {
		free(dst->pppd_plugin);
		dst->pppd_plugin = src->pppd_plugin;
	}
	if (src->pppd_ipparam) {
		free(dst->pppd_ipparam);
		dst->pppd_ipparam = src->pppd_ipparam;
	}
	if (src->pppd_ifname) {
		free(dst->pppd_ifname);
		dst->pppd_ifname = src->pppd_ifname;
	}
	if (src->pppd_call) {
		free(dst->pppd_call);
		dst->pppd_call = src->pppd_call;
	}
	if (src->pppd_accept_remote != invalid_cfg.pppd_accept_remote)
		dst->pppd_accept_remote = src->pppd_accept_remote;
#endif
#if HAVE_USR_SBIN_PPP
	if (src->ppp_system) {
		free(dst->ppp_system);
		dst->ppp_system = src->ppp_system;
	}
#endif
	if (src->ca_file) {
		free(dst->ca_file);
		dst->ca_file = src->ca_file;
	}
	if (src->user_cert) {
		free(dst->user_cert);
		if (strncmp(src->user_cert, "pkcs11:", 7) == 0)
			dst->use_engine = 1;
		dst->user_cert = src->user_cert;
	}
	if (src->user_key) {
		free(dst->user_key);
		dst->user_key = src->user_key;
	}
	if (src->pem_passphrase_set) {
		strcpy(dst->pem_passphrase, src->pem_passphrase);
		dst->pem_passphrase_set = src->pem_passphrase_set;
	}
	if (src->insecure_ssl != invalid_cfg.insecure_ssl)
		dst->insecure_ssl = src->insecure_ssl;
	if (src->cipher_list) {
		free(dst->cipher_list);
		dst->cipher_list = src->cipher_list;
	}
	if (src->min_tls > 0)
		dst->min_tls = src->min_tls;
	if (src->seclevel_1 != invalid_cfg.seclevel_1)
		dst->seclevel_1 = src->seclevel_1;
	if (src->cert_whitelist) {
		while (dst->cert_whitelist != NULL) {
			struct x509_digest *tmp = dst->cert_whitelist->next;

			free(dst->cert_whitelist);
			dst->cert_whitelist = tmp;
		}
		dst->cert_whitelist = src->cert_whitelist;
	}
	if (src->user_agent != invalid_cfg.user_agent)
		dst->user_agent = src->user_agent;
	if (src->hostcheck != invalid_cfg.hostcheck)
		dst->hostcheck = src->hostcheck;
	if (src->check_virtual_desktop != invalid_cfg.check_virtual_desktop)
		dst->check_virtual_desktop = src->check_virtual_desktop;
}
