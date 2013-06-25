/* support.c - support functions for pam_tacplus.c
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#include "support.h"
#include "pam_tacplus.h"

#include <stdlib.h>
#include <string.h>

tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
int tac_srv_no = 0;

char tac_service[64];
char tac_protocol[64];
char tac_prompt[64];

void _pam_log(int err, const char *format,...) {
    char msg[256];
    va_list args;

    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    openlog("PAM-tacplus", LOG_PID, LOG_AUTH);
    syslog(err, "%s", msg);
    va_end(args);
    closelog();
}

char *_pam_get_user(pam_handle_t *pamh) {
    int retval;
    char *user;

    retval = pam_get_user(pamh, (void *)&user, "Username: ");
    if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
        _pam_log(LOG_ERR, "unable to obtain username");
        user = NULL;
    }
    return user;
}

char *_pam_get_terminal(pam_handle_t *pamh) {
    int retval;
    char *tty;

    retval = pam_get_item(pamh, PAM_TTY, (void *)&tty);
    if (retval != PAM_SUCCESS || tty == NULL || *tty == '\0') {
        tty = ttyname(STDIN_FILENO);
        if(tty == NULL || *tty == '\0')
            tty = "unknown";
    }
    return tty;
}

char *_pam_get_rhost(pam_handle_t *pamh) {
    int retval;
    char *rhost;

    retval = pam_get_item(pamh, PAM_RHOST, (void *)&rhost);
    if (retval != PAM_SUCCESS || rhost == NULL || *rhost == '\0') {
        rhost = "unknown";
    }
    return rhost;
}

int converse(pam_handle_t * pamh, int nargs, const struct pam_message *message,
    struct pam_response **response) {

    int retval;
    struct pam_conv *conv;

    if ((retval = pam_get_item (pamh, PAM_CONV, (const void **)&conv)) == PAM_SUCCESS) {
        retval = conv->conv(nargs, &message, response, conv->appdata_ptr);

        if (retval != PAM_SUCCESS) {
            _pam_log(LOG_ERR, "(pam_tacplus) converse returned %d", retval);
            _pam_log(LOG_ERR, "that is: %s", pam_strerror (pamh, retval));
        }
    } else {
        _pam_log (LOG_ERR, "(pam_tacplus) converse failed to get pam_conv");
    }

    return retval;
}

/* stolen from pam_stress */
int tacacs_get_password (pam_handle_t * pamh, int flags
    ,int ctrl, char **password) {

    const void *pam_pass;
    char *pass = NULL;

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called", __FUNCTION__);

    if ( (ctrl & (PAM_TAC_TRY_FIRST_PASS | PAM_TAC_USE_FIRST_PASS))
        && (pam_get_item(pamh, PAM_AUTHTOK, &pam_pass) == PAM_SUCCESS)
        && (pam_pass != NULL) ) {
         if ((pass = strdup(pam_pass)) == NULL)
              return PAM_BUF_ERR;
    } else if ((ctrl & PAM_TAC_USE_FIRST_PASS)) {
         _pam_log(LOG_WARNING, "no forwarded password");
         return PAM_PERM_DENIED;
    } else {
         struct pam_message msg;
         struct pam_response *resp = NULL;
         int retval;

         /* set up conversation call */
         msg.msg_style = PAM_PROMPT_ECHO_OFF;

         if (!tac_prompt) {
             msg.msg = "Password: ";
         } else {
             msg.msg = tac_prompt;
         }

         if ((retval = converse (pamh, 1, &msg, &resp)) != PAM_SUCCESS)
             return retval;

         if (resp != NULL) {
             if (resp->resp == NULL && (ctrl & PAM_TAC_DEBUG))
                 _pam_log (LOG_DEBUG, "pam_sm_authenticate: NULL authtok given");

             pass = resp->resp;    /* remember this! */
             resp->resp = NULL;

             free(resp);
             resp = NULL;
         } else {
             if (ctrl & PAM_TAC_DEBUG) {
               _pam_log (LOG_DEBUG, "pam_sm_authenticate: no error reported");
               _pam_log (LOG_DEBUG, "getting password, but NULL returned!?");
             }
             return PAM_CONV_ERR;
         }
    }

    /*
       FIXME *password can still turn out as NULL
       and it can't be free()d when it's NULL
    */
    *password = pass;       /* this *MUST* be free()'d by this module */

    if(ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: obtained password", __FUNCTION__);

    return PAM_SUCCESS;
}

static
void _show_tac_server(tacplus_server_t *server, char *msg) {
    int i;

    _pam_log(LOG_DEBUG, "  %s\n", msg);
    _pam_log(LOG_DEBUG, "    host=%s\n", server->host);
    _pam_log(LOG_DEBUG, "    addr_cnt = %d\n", server->addr_cnt);
    for (i=0; i<TAC_PLUS_MAXADDRINFO; i++) {
        _pam_log(LOG_DEBUG, "    addr[%d] = %p\n", i, server->addr[i]);
    }
    _pam_log(LOG_DEBUG, "    key=%s\n", server->key);

    return;
}

static
void _show_tac_servers (tacplus_server_t *servers, int size) {
    int n;
    char msg[128];

    if (servers == NULL) {
        _pam_log(LOG_ERR, "%s(), servers are NULL\n", __FUNCTION__);
        return;
    }

    _pam_log(LOG_DEBUG, "%d servers defined\n", tac_srv_no);
    for (n=0; n<size; n++) {
        memset(msg, 0, 128);
        sprintf(msg, "Server %d:\n", n+1);
        _show_tac_server(&servers[n], msg);
    }

    return;
}

static
int _free_tac_server (tacplus_server_t *server) {
    int i;

    if (server != NULL) {
        if (server->host != NULL) {
            free(server->host);
            server->host = NULL;
        }

        for (i=0; i<server->addr_cnt; i++) {
            if (server->addr[i] != NULL) {
                freeaddrinfo(server->addr[i]);
                server->addr[i] = NULL;
            }
        }
        server->addr_cnt = 0;
    
        if (server->key != NULL) {
            server->key = NULL;
        }
    }

    return 1;
}

static
int _reset_tac_servers (tacplus_server_t *servers, int size) {
    int i;

    if (servers != NULL) {
        for (i=0; i<size; i++) {
            _free_tac_server(&servers[i]);
        }
    }

    tac_srv_no = 0;

    return 1;
}

static
int _pam_parse_server (const char *strsrv, tacplus_server_t *tac_server, const char *cur_secret) {
    char *strServer;
    struct addrinfo hints, *servers, *server;
    int rv;
    char *port;
    int addr_cnt;

    if (strsrv && strsrv[0]) {
        strServer = (char *) xcalloc(strlen(strsrv)+1, sizeof(char));
        strcpy(strServer, strsrv);
    } else {
        _pam_log(LOG_ERR, "empty server encountered");
        return 0;
    }

    port = strchr(strServer, ':');
    if (port != NULL)
        *port = '\0';

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;

    rv = getaddrinfo(strServer, (port == NULL ? "49" : port+1), &hints, &servers);
    if (rv == 0) {
        for(addr_cnt=0, server = servers;
            (server!=NULL && addr_cnt<TAC_PLUS_MAXADDRINFO);
            server = server->ai_next) {
            tac_server->addr[addr_cnt] = server;
            addr_cnt++;
        }
        tac_server->addr_cnt = addr_cnt;

        tac_server->host = (char *) xcalloc(strlen(strServer)+1, sizeof(char));
        strcpy(tac_server->host, strServer);

        if (cur_secret != NULL) {
            tac_server->key = cur_secret;
        }
    } else {
        _pam_log (LOG_ERR,
            "skip invalid server: %s (getaddrinfo: %s)",
            strServer, gai_strerror(rv));
        free (strServer);
        return 0;
    }

    free (strServer);

    return 1;
}

int _pam_parse (int argc, const char **argv, int reset_srv_list) {
    int ctrl = 0;
    const char *current_secret = NULL;

    /* Need to initialize/re-initialize the tac_servers structure */
    /* otherwise the list will grow with each call */
    if (reset_srv_list) {
        tac_srv_no = 0;
        _reset_tac_servers(tac_srv, TAC_PLUS_MAXSERVERS);
    }

    tac_service[0] = 0;
    tac_protocol[0] = 0;
    tac_prompt[0] = 0;
    tac_login[0] = 0;

    for (ctrl = 0; argc-- > 0; ++argv) {
        if (!strcmp (*argv, "debug")) { /* all */
            ctrl |= PAM_TAC_DEBUG;
        } else if (!strcmp (*argv, "use_first_pass")) {
            ctrl |= PAM_TAC_USE_FIRST_PASS;
        } else if (!strcmp (*argv, "try_first_pass")) { 
            ctrl |= PAM_TAC_TRY_FIRST_PASS;
        } else if (!strncmp (*argv, "service=", 8)) { /* author & acct */
            xstrcpy (tac_service, *argv + 8, sizeof(tac_service));
        } else if (!strncmp (*argv, "protocol=", 9)) { /* author & acct */
            xstrcpy (tac_protocol, *argv + 9, sizeof(tac_protocol));
        } else if (!strncmp (*argv, "prompt=", 7)) { /* authentication */
            xstrcpy (tac_prompt, *argv + 7, sizeof(tac_prompt));
            /* Replace _ with space */
            int chr;
            for (chr = 0; chr < strlen(tac_prompt); chr++) {
                if (tac_prompt[chr] == '_') {
                    tac_prompt[chr] = ' ';
                }
            }
        } else if (!strncmp (*argv, "login=", 6)) {
            xstrcpy (tac_login, *argv + 6, sizeof(tac_login));
        } else if (!strcmp (*argv, "acct_all")) {
            ctrl |= PAM_TAC_ACCT;
        } else if (!strncmp (*argv, "server=", 7)) { /* authen & acct */
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) { 
                if (_pam_parse_server(*argv+7, &tac_srv[tac_srv_no], current_secret)) {
                    tac_srv_no++;
                }
            } else {
                _pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
                    TAC_PLUS_MAXSERVERS);
            }
        } else if (!strncmp (*argv, "secret=", 7)) {
            int i;

            current_secret = *argv + 7;     /* points right into argv (which is const) */

            /* if 'secret=' was given after a 'server=' parameter, fill in the current secret */
            for(i = tac_srv_no-1; i >= 0; i--) {
                if (tac_srv[i].key != NULL)
                    break;

                tac_srv[i].key = current_secret;
            }
        } else if (!strncmp (*argv, "timeout=", 8)) {
            /* FIXME atoi() doesn't handle invalid numeric strings well */
            tac_timeout = atoi(*argv + 8);

            if (tac_timeout < 0)
                tac_timeout = 0;
        } else {
            _pam_log (LOG_WARNING, "unrecognized option: %s", *argv);
        }
    }

    if (ctrl & PAM_TAC_DEBUG) {
        int n;

        _pam_log(LOG_DEBUG, "%d servers defined", tac_srv_no);

        for(n = 0; n < tac_srv_no; n++) {
            _pam_log(LOG_DEBUG, "server[%d] { addr=%s, key='%s' }", n, tac_srv[n].host, tac_srv[n].key);
        }

        _pam_log(LOG_DEBUG, "tac_service='%s'", tac_service);
        _pam_log(LOG_DEBUG, "tac_protocol='%s'", tac_protocol);
        _pam_log(LOG_DEBUG, "tac_prompt='%s'", tac_prompt);
        _pam_log(LOG_DEBUG, "tac_login='%s'", tac_login);
    }

    return ctrl;
}    /* _pam_parse */

int _duplicate_server(tacplus_server_t *dup_srv, tacplus_server_t *ori_srv) {
    int i;

    if (dup_srv==NULL || ori_srv==NULL) {
        return 0;
    }

    _free_tac_server(dup_srv);

    dup_srv->host = (char *) xcalloc(strlen(ori_srv->host)+1, sizeof(char));
    strcpy(dup_srv->host, ori_srv->host);

    for (i=0; i<TAC_PLUS_MAXADDRINFO; i++) {
        dup_srv->addr[i] = ori_srv->addr[i];
    }
    dup_srv->addr_cnt = ori_srv->addr_cnt;

    dup_srv->key = (char *) xcalloc(strlen(ori_srv->key)+1, sizeof(char));
    strcpy(dup_srv->key, ori_srv->key);

    return 1;
}

