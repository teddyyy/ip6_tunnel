#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>

#include "utils.h"
#include "tunnel.h"
#include "ip_common.h"

#define IP6_FLOWINFO_TCLASS	htonl(0x0FF00000)
#define IP6_FLOWINFO_FLOWLABEL	htonl(0x000FFFFF)

#define DEFAULT_TNL_HOP_LIMIT	(64)

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: ip -f inet6 skinny { add | change | del | show } [ NAME ]\n");
	fprintf(stderr, "          [ mode { ip6ip6 } ]\n");
	fprintf(stderr, "          [ remote ADDR local ADDR ] [ dev PHYS_DEV ]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where: NAME      := STRING\n");
	fprintf(stderr, "       ADDR      := IPV6_ADDRESS\n");
	fprintf(stderr, "       ELIM      := { none | 0..255 }(default=%d)\n",
		IPV6_DEFAULT_TNL_ENCAP_LIMIT);
	fprintf(stderr, "       TTL       := 0..255 (default=%d)\n",
		DEFAULT_TNL_HOP_LIMIT);
	exit(-1);
}

static void print_tunnel(struct ip6_tnl_parm2 *p)
{
	char s1[1024];
	char s2[1024];

	/* Do not use format_host() for local addr,
	 * symbolic name will not be useful.
	 */
	printf("%s: %s/ipv6 remote %s local %s",
	       p->name,
	       tnl_strproto(p->proto),
	       format_host_r(AF_INET6, 16, &p->raddr, s1, sizeof(s1)),
	       rt_addr_n2a_r(AF_INET6, 16, &p->laddr, s2, sizeof(s2)));
	if (p->link) {
		const char *n = ll_index_to_name(p->link);

		if (n)
			printf(" dev %s", n);
	}

	if (p->flags & IP6_TNL_F_IGN_ENCAP_LIMIT)
		printf(" encaplimit none");
	else
		printf(" encaplimit %u", p->encap_limit);

	printf(" hoplimit %u", p->hop_limit);

}

static int parse_args(int argc, char **argv, int cmd, struct ip6_tnl_parm2 *p)
{
	int count = 0;
	char medium[IFNAMSIZ] = {};

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			NEXT_ARG();
			if (strcmp(*argv, "ip6ip6") == 0 ) {
				p->proto = IPPROTO_IPV6;
			} else {
				fprintf(stderr, "Unknown tunnel mode \"%s\"\n", *argv);
				exit(-1);
			}
		} else if (strcmp(*argv, "remote") == 0) {
			inet_prefix raddr;

			NEXT_ARG();
			get_prefix(&raddr, *argv, preferred_family);
			if (raddr.family == AF_UNSPEC)
				invarg("\"remote\" address family is AF_UNSPEC", *argv);
			memcpy(&p->raddr, &raddr.data, sizeof(p->raddr));
		} else if (strcmp(*argv, "local") == 0) {
			inet_prefix laddr;

			NEXT_ARG();
			get_prefix(&laddr, *argv, preferred_family);
			if (laddr.family == AF_UNSPEC)
				invarg("\"local\" address family is AF_UNSPEC", *argv);
			memcpy(&p->laddr, &laddr.data, sizeof(p->laddr));
		} else if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			strncpy(medium, *argv, IFNAMSIZ - 1);
		} else {
			if (strcmp(*argv, "name") == 0) {
				NEXT_ARG();
			} else if (matches(*argv, "help") == 0)
				usage();
			if (p->name[0])
				duparg2("name", *argv);
			strncpy(p->name, *argv, IFNAMSIZ - 1);
			if (cmd == SIOCCHGTUNNEL && count == 0) {
				struct ip6_tnl_parm2 old_p = {};

				if (tnl_get_ioctl(*argv, &old_p))
					return -1;
				*p = old_p;
			}
		}
		count++;
		argc--; argv++;
	}
	if (medium[0]) {
		p->link = ll_name_to_index(medium);
		if (p->link == 0) {
			fprintf(stderr, "Cannot find device \"%s\"\n", medium);
			return -1;
		}
	}
	return 0;
}

static void ip6_tnl_parm_init(struct ip6_tnl_parm2 *p, int apply_default)
{
	memset(p, 0, sizeof(*p));
	p->proto = IPPROTO_IPV6;
	if (apply_default) {
		p->hop_limit = DEFAULT_TNL_HOP_LIMIT;
		p->encap_limit = IPV6_DEFAULT_TNL_ENCAP_LIMIT;
	}
}

/*
 * @p1: user specified parameter
 * @p2: database entry
 */
static int ip6_tnl_parm_match(const struct ip6_tnl_parm2 *p1,
			      const struct ip6_tnl_parm2 *p2)
{
	return ((!p1->link || p1->link == p2->link) &&
		(!p1->name[0] || strcmp(p1->name, p2->name) == 0) &&
		(IN6_IS_ADDR_UNSPECIFIED(&p1->laddr) ||
		 IN6_ARE_ADDR_EQUAL(&p1->laddr, &p2->laddr)) &&
		(IN6_IS_ADDR_UNSPECIFIED(&p1->raddr) ||
		 IN6_ARE_ADDR_EQUAL(&p1->raddr, &p2->raddr)) &&
		(!p1->proto || !p2->proto || p1->proto == p2->proto) &&
		(!p1->encap_limit || p1->encap_limit == p2->encap_limit) &&
		(!p1->hop_limit || p1->hop_limit == p2->hop_limit) &&
		(!(p1->flowinfo & IP6_FLOWINFO_TCLASS) ||
		 !((p1->flowinfo ^ p2->flowinfo) & IP6_FLOWINFO_TCLASS)) &&
		(!(p1->flowinfo & IP6_FLOWINFO_FLOWLABEL) ||
		 !((p1->flowinfo ^ p2->flowinfo) & IP6_FLOWINFO_FLOWLABEL)) &&
		(!p1->flags || (p1->flags & p2->flags)));
}

static int do_tunnels_list(struct ip6_tnl_parm2 *p)
{
	char buf[512];
	int err = -1;
	FILE *fp = fopen("/proc/net/dev", "r");

	if (fp == NULL) {
		perror("fopen");
		return -1;
	}

	/* skip two lines at the begenning of the file */
	if (!fgets(buf, sizeof(buf), fp) ||
	    !fgets(buf, sizeof(buf), fp)) {
		fprintf(stderr, "/proc/net/dev read error\n");
		goto end;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char name[IFNAMSIZ];
		int index, type;
		struct ip6_tnl_parm2 p1 = {};
		char *ptr;

		buf[sizeof(buf) - 1] = '\0';
		if ((ptr = strchr(buf, ':')) == NULL ||
		    (*ptr++ = 0, sscanf(buf, "%s", name) != 1)) {
			fprintf(stderr, "Wrong format for /proc/net/dev. Giving up.\n");
			goto end;
		}
		if (p->name[0] && strcmp(p->name, name))
			continue;
		index = ll_name_to_index(name);
		if (index == 0)
			continue;
		type = ll_index_to_type(index);
		if (type == -1) {
			fprintf(stderr, "Failed to get type of \"%s\"\n", name);
			continue;
		}
		if (type != ARPHRD_TUNNEL6 && type != ARPHRD_IP6GRE)
			continue;
		ip6_tnl_parm_init(&p1, 0);
		if (type == ARPHRD_IP6GRE)
			p1.proto = IPPROTO_GRE;
		strcpy(p1.name, name);
		p1.link = ll_name_to_index(p1.name);
		if (p1.link == 0)
			continue;
		if (tnl_get_ioctl(p1.name, &p1))
			continue;
		if (!ip6_tnl_parm_match(p, &p1))
			continue;
		print_tunnel(&p1);
		if (show_stats)
			tnl_print_stats(ptr);
		printf("\n");
	}
	err = 0;
 end:
	fclose(fp);
	return err;
}

static int do_show(int argc, char **argv)
{
	struct ip6_tnl_parm2 p;

	ll_init_map(&rth);
	ip6_tnl_parm_init(&p, 0);
	p.proto = 0;  /* default to any */

	if (parse_args(argc, argv, SIOCGETTUNNEL, &p) < 0)
		return -1;

	if (!p.name[0] || show_stats)
		do_tunnels_list(&p);
	else {
		if (tnl_get_ioctl(p.name, &p))
			return -1;
		print_tunnel(&p);
		printf("\n");
	}

	return 0;
}

static int do_add(int cmd, int argc, char **argv)
{
	struct ip6_tnl_parm2 p;
	const char *basedev = "ip6skn0";

	ip6_tnl_parm_init(&p, 1);

	if (parse_args(argc, argv, cmd, &p) < 0)
		return -1;

	return tnl_add_ioctl(cmd, basedev, p.name, &p);
}

static int do_del(int argc, char **argv)
{
	struct ip6_tnl_parm2 p;
	const char *basedev = "ip6skn0";

	ip6_tnl_parm_init(&p, 1);

	if (parse_args(argc, argv, SIOCDELTUNNEL, &p) < 0)
		return -1;

	return tnl_del_ioctl(basedev, p.name, &p);
}

int do_ipskinny(int argc, char **argv)
{
	switch (preferred_family) {
	case AF_UNSPEC:
		preferred_family = AF_INET6;
		break;
	case AF_INET6:
		break;
	default:
		fprintf(stderr, "Unsupported protocol family: %d\n", preferred_family);
		exit(-1);
	}

	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return do_add(SIOCADDTUNNEL, argc - 1, argv + 1);
		if (matches(*argv, "change") == 0)
			return do_add(SIOCCHGTUNNEL, argc - 1, argv + 1);
		if (matches(*argv, "delete") == 0)
			return do_del(argc - 1, argv + 1);
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return do_show(argc - 1, argv + 1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return do_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip -f inet6 tunnel help\".\n", *argv);
	exit(-1);
}
