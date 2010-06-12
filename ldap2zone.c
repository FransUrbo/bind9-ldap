/* $Id: ldap2zone.c,v 1.5 2010-06-12 20:16:19 turbo Exp $ */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <ldap.h>
#include <errno.h>
#include <getopt.h>

#define VERSION    "0.1/TF.3"

//#define SEARCH_DEBUG 1
//#define CONNECT_DEBUG 1

/* Ldap error checking */
void ldap_result_check (LDAP *conn, char *msg, int err);

#ifdef SECUREBIND_SASL
//#define SASL_DEBUG 1
#include <slapd/lutil_ldap.h>
#include <sasl/sasl.h>
#endif

struct string {
    void *data;
    size_t len;
};

struct assstack_entry {
    struct string key;
    struct string val;
    struct assstack_entry *next;
};

struct assstack_entry *assstack_find(struct assstack_entry *stack, struct string *key);
void assstack_push(struct assstack_entry **stack, struct assstack_entry *item);
void assstack_insertbottom(struct assstack_entry **stack, struct assstack_entry *item);
void printsoa(struct string *soa);
void printrrs(char *defaultttl, struct assstack_entry *item);
void print_zone(char *defaultttl, struct assstack_entry *stack);
void usage(char *name);
void err(char *name, const char *msg);
int putrr(struct assstack_entry **stack, struct berval *name, char *type, char *ttl, struct berval *val);

struct assstack_entry *assstack_find(struct assstack_entry *stack, struct string *key) {
    for (; stack; stack = stack->next)
	if (stack->key.len == key->len && !memcmp(stack->key.data, key->data, key->len))
	    return stack;
    return NULL;
}

void assstack_push(struct assstack_entry **stack, struct assstack_entry *item) {
    item->next = *stack;
    *stack = item;
}

void assstack_insertbottom(struct assstack_entry **stack, struct assstack_entry *item) {
    struct assstack_entry *p;
    
    item->next = NULL;
    if (!*stack) {
	*stack = item;
	return;
    }
    /* find end, should keep track of end somewhere */
    /* really a queue, not a stack */
    p = *stack;
    while (p->next)
	p = p->next;
    p->next = item;
}

void printsoa(struct string *soa) {
    char *s;
    size_t i;
    
    s = (char *)soa->data;
    i = 0;
    while (i < soa->len) {
	putchar(s[i]);
	if (s[i++] == ' ')
	    break;
    }
    while (i < soa->len) {
	putchar(s[i]);
	if (s[i++] == ' ')
	    break;
    } 
    printf("(\n\t\t\t\t");
    while (i < soa->len) {
	putchar(s[i]);
	if (s[i++] == ' ')
	    break;
    }
    printf("; Serialnumber\n\t\t\t\t");
    while (i < soa->len) {
	if (s[i] == ' ')
	    break;
	putchar(s[i++]);
    }
    i++;
    printf("\t; Refresh\n\t\t\t\t");
    while (i < soa->len) {
	if (s[i] == ' ')
	    break;
	putchar(s[i++]);
    }
    i++;
    printf("\t; Retry\n\t\t\t\t");
    while (i < soa->len) {
	if (s[i] == ' ')
	    break;
	putchar(s[i++]);
    }
    i++;
    printf("\t; Expire\n\t\t\t\t");
    while (i < soa->len) {
	putchar(s[i++]);
    }
    printf(" )\t; Minimum TTL\n");
}

void printrrs(char *defaultttl, struct assstack_entry *item) {
    struct assstack_entry *stack;
    char *s;
    int first;
    size_t i;
    char *ttl, *type;
    int top;
    
    s = (char *)item->key.data;

    if (item->key.len == 1 && *s == '@') {
	top = 1;
	printf("@\t");
    } else {
	top = 0;
	for (i = 0; i < item->key.len; i++)
	    putchar(s[i]);
	if (item->key.len < 8)
	    putchar('\t');
	putchar('\t');
    }
    
    first = 1;
    for (stack = (struct assstack_entry *) item->val.data; stack; stack = stack->next) {
	ttl = (char *)stack->key.data;
	s = strchr(ttl, ' ');
	*s++ = '\0';
	type = s;
	
	if (first)
	    first = 0;
        else
	    printf("\t\t");
	    
	if (strcmp(defaultttl, ttl))
	    printf("%s", ttl);
	putchar('\t');
	
	if (top) {
	    top = 0;
	    printf("IN\t%s\t", type);
	    /* Should always be SOA here */
	    if (!strcmp(type, "SOA")) {
		printsoa(&stack->val);
		continue;
	    }
	} else
	    printf("%s\t", type);

	s = (char *)stack->val.data;
	for (i = 0; i < stack->val.len; i++)
	    putchar(s[i]);
	putchar('\n');
    }
}

void print_zone(char *defaultttl, struct assstack_entry *stack) {
    printf("$TTL %s\n", defaultttl);
    for (; stack; stack = stack->next)
	printrrs(defaultttl, stack);
};

/* This function is ugly with the 'sole purpose' to make it look
 * good no matter how it's compiled! */
void usage(char *name) {
    fprintf(stderr, "Usage: %s "
	    "[-D BIND DN] [-w BIND PASSWORD] "
#ifdef SECUREBIND_SASL
	    "] "
#endif
	    "\n"
#ifdef LDAPDB_TLS
	    "       [-Z[Z] Issue StartTLS extended operation]\n"
#endif
#ifdef SECUREBIND_SASL
	    "       [-O SASL security properties] [-Q SASL Quiet mode] [-R SASL realm]\n"
	    "       [-U Username for SASL bind] [-X Authzid for SASL bind] [-Y SASL mechanism]\n"
#endif
	    "       <ZONE NAME> <LDAP-URL> <DEFAULT TTL> [SERIAL]\n", name);
    exit(1);
};

void err(char *name, const char *msg) {
    fprintf(stderr, "%s: %s\n", name, msg);
    exit(1);
};

int putrr(struct assstack_entry **stack, struct berval *name, char *type, char *ttl, struct berval *val) {
    struct string key;
    struct assstack_entry *rr, *rrdata;
    
    /* Do nothing if name or value have 0 length */
    if (!name->bv_len || !val->bv_len)
	return 0;

    /* see if already have an entry for this name */
    key.len = name->bv_len;
    key.data = name->bv_val;

    rr = assstack_find(*stack, &key);
    if (!rr) {
	/* Not found, create and push new entry */
	rr = (struct assstack_entry *) malloc(sizeof(struct assstack_entry));
	if (!rr)
	    return -1;
	rr->key.len = name->bv_len;
	rr->key.data = (void *) malloc(rr->key.len);
	if (!rr->key.data) {
	    free(rr);
	    return -1;
	}
	memcpy(rr->key.data, name->bv_val, name->bv_len);
	rr->val.len = sizeof(void *);
	rr->val.data = NULL;
	if (name->bv_len == 1 && *(char *)name->bv_val == '@')
	    assstack_push(stack, rr);
	else
	    assstack_insertbottom(stack, rr);
    }

    rrdata = (struct assstack_entry *) malloc(sizeof(struct assstack_entry));
    if (!rrdata) {
	free(rr->key.data);
	free(rr);
	return -1;
    }
    rrdata->key.len = strlen(type) + strlen(ttl) + 1;
    rrdata->key.data = (void *) malloc(rrdata->key.len);
    if (!rrdata->key.data) {
	free(rrdata);
	free(rr->key.data);
	free(rr);
	return -1;
    }
    sprintf((char *)rrdata->key.data, "%s %s", ttl, type);
	
    rrdata->val.len = val->bv_len;
    rrdata->val.data = (void *) malloc(val->bv_len);
    if (!rrdata->val.data) {
	free(rrdata->key.data);
	free(rrdata);
	free(rr->key.data);
	free(rr);
	return -1;
    }
    memcpy(rrdata->val.data, val->bv_val, val->bv_len);

    if (!strcmp(type, "SOA"))
	assstack_push((struct assstack_entry **) &(rr->val.data), rrdata);
    else
	assstack_insertbottom((struct assstack_entry **) &(rr->val.data), rrdata);
    return 0;
}

int main(int argc, char **argv) {
    char *s, *hostporturl, *base = NULL;
    char *ttl, *defaultttl;
    LDAP *ld = NULL;
    char *fltr = NULL;
    LDAPMessage *res, *e;
    char *a, **ttlvals, **soavals, *serial;
    struct berval **vals, **names;
    char type[64];
    BerElement *ptr;
    int i, j, rc, msgid, topt, bound = 0;
    struct assstack_entry *zone = NULL;
    extern char *optarg;
    char *binddn = NULL, *bindpw = NULL;

    char *zonename = NULL, *serialno = NULL;
#ifdef LDAPDB_TLS
    int use_tls = 0;
#endif
#if defined(LDAPDB_TLS) || defined(SECUREBIND_SASL)
    int protocol;
#endif
#ifdef SECUREBIND_SASL
    void *defaults;
    unsigned	 sasl_flags	= LDAP_SASL_AUTOMATIC;
    char	*sasl_secprops	= NULL;
    char	*sasl_realm	= NULL;
    char	*sasl_authc_id	= NULL;
    char	*sasl_authz_id	= NULL;
    char	*sasl_mech	= NULL;
    int		 authmethod	= LDAP_AUTH_SASL;
#ifdef SASL_DEBUG
    char	*id		= NULL;
#endif
#endif    

    if (argc < 4)
        usage(argv[0]);

    while ((topt = getopt ((int) argc, argv, "D:w:Z?O:QR:U:X:Y:IV")) != -1) {
      switch (topt) {
      case 'V':
	printf("%s\n", VERSION);
	exit(0);

      case 'D':
#ifdef SECUREBIND_SASL
	authmethod = -1;
#endif
	binddn = strdup (optarg);
	break;
      case 'w':
	bindpw = strdup (optarg);
	break;

#ifdef LDAPDB_TLS
      case 'Z':
	/* Issue StartTLS (Transport Layer Security) extended operation. */
	++use_tls;
	break;
#endif

#if defined(SECUREBIND_SASL)
      case 'O':
	/* SASL security properties */
	sasl_secprops = strdup (optarg);
	break;
      case 'Q':
	/* SASL Quiet mode */
	sasl_flags = LDAP_SASL_QUIET;
	break;
      case 'R':
	/* SASL realm */
	sasl_realm = strdup (optarg);
	break;
      case 'U':
	/* Username for SASL bind.  The syntax of the username depends
	 * on the actual SASL mechanism used.
	 */
	sasl_authc_id = strdup (optarg);
	break;
      case 'X':
	/* Requested authorization ID for SASL bind. Authzid must be
	 * one of the following formats:
	 *   dn:<distinguished name>
	 * or
	 *   u:<username>
	 */
	sasl_authz_id = strdup (optarg);
	break;
      case 'Y':
	/* the SASL mechanism to be used for authentication. If it's
	 * not specified, the program will choose the best mechanism
	 * the server knows.
	 */
	sasl_mech = strdup (optarg);
	break;
      case 'I':
	/* SASL Interactive mode. */
	sasl_flags = LDAP_SASL_INTERACTIVE;
	break;
#endif

      case '?':
      default:
        usage(argv[0]);
	exit (0);
      }
    }

    /* ---------------- */

    zonename    = argv[optind++];
    hostporturl = argv[optind++];

    if (!hostporturl)
      err(argv[0], "LDAP URL not specified");
    if (hostporturl != strstr( hostporturl, "ldap"))
	err(argv[0], "Not an LDAP URL");

    s = strchr(hostporturl, ':');

    if (!s || strlen(s) < 3 || s[1] != '/' || s[2] != '/')
	err(argv[0], "Not an LDAP URL");

    s = strchr(s+3, '/');
    if (s) {
	*s++ = '\0';
	base = s;
	s = strchr(base, '?');
	if (s)
	    err(argv[0], "LDAP URL can only contain host, port and base");
    }

    if (!base)
      err(argv[0], "LDAP search base not specified");

    if(argv[optind])
      defaultttl = argv[optind++];
    else
      err(argv[0], "Default TTL not specified");

    if(argv[optind])
      serialno = argv[optind++];

    /* ---------------- */

    rc = ldap_initialize(&ld, hostporturl);
    if (rc != LDAP_SUCCESS)
	err(argv[0], "ldap_initialize() failed");

#if defined(LDAPDB_TLS) || defined(SECUREBIND_SASL)
    /* Directly stolen from the ldapsearch.c file in OpenLDAP (v2.0.27) */
    if (
#ifdef LDAPDB_TLS
	use_tls
#endif
#if defined(LDAPDB_TLS) && defined(SECUREBIND_SASL)
	||
#endif
#ifdef SECUREBIND_SASL
	(authmethod == LDAP_AUTH_SASL)
#endif
	) {
      /* Make sure we use LDAPv3 when trying TLS or SASL (a requirenment). */
      protocol = LDAP_VERSION3;
      if(ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol) != LDAP_OPT_SUCCESS ) {
	fprintf (stderr, "Failed setting LDAP version to LDAPv3: %s\n", strerror (errno));
	exit (-1);
      }
    }
#endif

#ifdef LDAPDB_TLS
    if(use_tls) {
      /* Initialize the TLS connection */
      if(ldap_start_tls_s(ld, NULL, NULL) != LDAP_SUCCESS) {
	if(use_tls > 1) {
	  fprintf (stderr, "Starting TLS failed: %s\n", strerror (errno));
	  exit (-1);
	} else
	  ldap_perror(ld, "ldap_start_tls_s");
      }
#ifdef CONNECT_DEBUG
      else
	fprintf (stderr, "Successfully started TLS\n");
#endif
    }
#endif

#ifdef SECUREBIND_SASL
    if (authmethod != LDAP_AUTH_SASL) {
#endif
      if (binddn && !bindpw)
	bindpw = getpass("Enter LDAP Password: ");
#ifdef SECUREBIND_SASL
    }    
#endif

#ifdef SECUREBIND_SASL
    if (authmethod == LDAP_AUTH_SASL) {
      if (sasl_secprops != NULL ) {
	rc = ldap_set_option (ld, LDAP_OPT_X_SASL_SECPROPS, (void *) sasl_secprops );
	if( rc != LDAP_OPT_SUCCESS ) {
	  fprintf (stderr, "Could not set LDAP_OPT_X_SASL_SECPROPS: %s\n", sasl_secprops );
	  exit (-1);
	}
#ifdef SASL_DEBUG
	else
	  fprintf (stderr, " Successfully set SASL secprops\n");
#endif
      }
      
      defaults = lutil_sasl_defaults (ld, sasl_mech, sasl_realm, sasl_authc_id, bindpw, sasl_authz_id);

#ifdef SASL_DEBUG
      if(sasl_authc_id)
	id = sasl_authc_id;
      else if(sasl_authz_id)
	id = sasl_authz_id;
#ifdef SASL_DEBUG
      fprintf (stderr, "Initializing SASL LDAP Connection to %s as %s@%s w/ pass '%s'\n", hostporturl, id, sasl_realm, bindpw);
#endif
#endif

      rc = ldap_sasl_interactive_bind_s (ld, binddn, sasl_mech, NULL, NULL,
					 sasl_flags, lutil_sasl_interact, defaults);
      
      lutil_sasl_freedefs (defaults);
      if (rc != LDAP_SUCCESS ) {
	ldap_perror (ld, "ldap_sasl_interactive_bind_s");
	exit (-1);
      }
    } else {
#endif
#ifdef CONNECT_DEBUG
    fprintf (stderr, "Initializing simple LDAP Connection to %s as '%s' w/ pass '%s'\n", hostporturl, binddn, bindpw);
#endif
    rc = ldap_simple_bind_s (ld, binddn, bindpw);
    ldap_result_check (ld, "ldap_simple_bind_s", rc);
#ifdef SECUREBIND_SASL
    }
#endif
    bound = 1;
    /* ---------------- */

    if (serialno) {
	/* serial number specified, check if different from one in SOA */
	fltr = (char *)malloc(strlen(zonename) + strlen("(&(relativeDomainName=@)(zoneName=))") + 1);
	sprintf(fltr, "(&(relativeDomainName=@)(zoneName=%s))", zonename);
#ifdef SEARCH_DEBUG
	fprintf(stderr, "ldap_search(ld, '%s', 'sub', '%s', NULL, 0)\n", base, fltr);
#endif
	msgid = ldap_search(ld, base, LDAP_SCOPE_SUBTREE, fltr, NULL, 0);
	if (msgid == -1) {
	  if(bound) ldap_unbind_s(ld);
	  err(argv[0], "ldap_search() failed");
	}

	while ((rc = ldap_result(ld, msgid, 0, NULL, &res)) != LDAP_RES_SEARCH_RESULT ) {
	    /* not supporting continuation references at present */
	    if (rc != LDAP_RES_SEARCH_ENTRY) {
	      if(bound) ldap_unbind_s(ld);
		err(argv[0], "ldap_result() returned cont.ref? Exiting");
	    }

	    /* only one entry per result message */
	    e = ldap_first_entry(ld, res);
	    if (e == NULL) {
		ldap_msgfree(res);
		if(bound) ldap_unbind_s(ld);
		err(argv[0], "ldap_first_entry() failed");
	    }
	
	    soavals = ldap_get_values(ld, e, "SOARecord");
	    if (soavals)
		break;
	}

	ldap_msgfree(res);
	if (!soavals) {
	  if(bound) ldap_unbind_s(ld);
	  err(argv[0], "No SOA Record found");
	}
	
	/* We have a SOA, compare serial numbers */
	/* Only checkinf first value, should be only one */
	s = strchr(soavals[0], ' ');
	s++;
	s = strchr(s, ' ');
	s++;
	serial = s;
	s = strchr(s, ' ');
	*s = '\0';
	if (!strcmp(serial, serialno)) {
	    ldap_value_free(soavals);
	    if(bound) ldap_unbind_s(ld);
	    err(argv[0], "serial numbers match");
	}

	ldap_value_free(soavals);
    }

    if (!fltr)
	fltr = (char *)malloc(strlen(zonename) + strlen("(zoneName=)") + 1);
    if (!fltr) {
	if(bound) ldap_unbind_s(ld);
	err(argv[0], "Malloc failed");
    }

    sprintf(fltr, "(zoneName=%s)", zonename);
#ifdef SEARCH_DEBUG
    fprintf(stderr, "ldap_search(ld, '%s', 'sub', '%s', NULL, 0)\n", base, fltr);
#endif

    msgid = ldap_search(ld, base, LDAP_SCOPE_SUBTREE, fltr, NULL, 0);
    if (msgid == -1) {
	if(bound) ldap_unbind_s(ld);
	err(argv[0], "ldap_search() failed");
    }

    while ((rc = ldap_result(ld, msgid, 0, NULL, &res)) != LDAP_RES_SEARCH_RESULT ) {
	/* not supporting continuation references at present */
	if (rc != LDAP_RES_SEARCH_ENTRY) {
	    if(bound) ldap_unbind_s(ld);
	    err(argv[0], "ldap_result() returned cont.ref? Exiting");
	}

	/* only one entry per result message */
	e = ldap_first_entry(ld, res);
	if (e == NULL) {
	    if(bound) ldap_unbind_s(ld);
	    ldap_msgfree(res);
	    err(argv[0], "ldap_first_entry() failed");
	}
	
	names = ldap_get_values_len(ld, e, "relativeDomainName");
	if (!names)
	    continue;
	
	ttlvals = ldap_get_values(ld, e, "dNSTTL");
	ttl = ttlvals ? ttlvals[0] : defaultttl;

	for (a = ldap_first_attribute(ld, e, &ptr); a != NULL; a = ldap_next_attribute(ld, e, ptr)) {
	    char *s;

	    for (s = a; *s; s++)
		*s = toupper(*s);
	    s = strstr(a, "RECORD");
	    if ((s == NULL) || (s == a) || (s - a >= (signed int)sizeof(type))) {
		ldap_memfree(a);
		continue;
	    }
			
	    strncpy(type, a, s - a);
	    type[s - a] = '\0';
	    vals = ldap_get_values_len(ld, e, a);
	    if (vals) {
		for (i = 0; vals[i]; i++)
		    for (j = 0; names[j]; j++)
			if (putrr(&zone, names[j], type, ttl, vals[i]))
			    err(argv[0], "malloc failed");
		ldap_value_free_len(vals);
	    }
	    ldap_memfree(a);
	}

	if (ptr)
	    ber_free(ptr, 0);
	if (ttlvals)
	    ldap_value_free(ttlvals);
	ldap_value_free_len(names);
	/* free this result */
	ldap_msgfree(res);
    }

    /* free final result */
    ldap_msgfree(res);

    print_zone(defaultttl, zone);

    if(bound) ldap_unbind_s(ld);
    return 0;
}

/* Like isc_result_check, only for LDAP */
void ldap_result_check (LDAP *conn, char *msg, int err) {
  if ((err != LDAP_SUCCESS) && (err != LDAP_ALREADY_EXISTS)) {
    fprintf(stderr, "%s\n", msg);
    ldap_perror (conn, msg);
    ldap_unbind_s (conn);
    exit (-1);
  }
}
