#include "nl80211_stats.h"

struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
  [NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
  [NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
  [NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
  [NL80211_STA_INFO_RX_PACKETS] = { .type = NLA_U32 },
  [NL80211_STA_INFO_TX_PACKETS] = { .type = NLA_U32 },
  [NL80211_STA_INFO_SIGNAL] = { .type = NLA_U8 },
  [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
  [NL80211_STA_INFO_TX_FAILED] = { .type = NLA_U32 },
  [NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
  [NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
  [NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
};

struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
  [NL80211_RATE_INFO_MCS] = { .type = NLA_U8 },
  [NL80211_RATE_INFO_BITRATE32] = { .type = NLA_U32 },
  [NL80211_RATE_INFO_40_MHZ_WIDTH] = { .type = NLA_FLAG },
  [NL80211_RATE_INFO_SHORT_GI] = { .type = NLA_FLAG },
  [NL80211_RATE_INFO_VHT_MCS] = { .type = NLA_U8 },
  [NL80211_RATE_INFO_VHT_NSS] = { .type = NLA_U8 },
//  [NL80211_RATE_INFO_HE_NSS] = { .type = NLA_U8 },
};

struct link_result {
        uint8_t bssid[8];
        bool link_found;
        bool anything_found;
};


void mac_addr_n2a(char *mac_addr, const unsigned char *arg) {
	int i, l;

	l = 0;
	for (i = 0; i < ETH_ALEN ; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}


void * nl80211_cmd(Netlink *nl, struct nl_msg *msg, int flags, uint8_t cmd) {
  return genlmsg_put(msg, 0, 0, nl->id, 0, flags, cmd, 0);
}

static int send_and_recv(Netlink *drv,
                          struct nl_sock *nl_socket, struct nl_msg *msg,
                          int (*valid_handler)(struct nl_msg *, void *),
                          void *valid_data) {
  struct nl_cb *cb;
  int err = -ENOMEM;

  cb = nl_cb_clone(drv->nl_cb);
  if (!cb)
    goto out;

  err = nl_send_auto_complete(nl_socket, msg);
  if (err < 0)
    goto out;

  err = 1;

  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
  nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

  if (valid_handler)
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, valid_data);

  while (err > 0)
    nl_recvmsgs(nl_socket, cb);
  out:
    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}
 
 
static int send_and_recv_msgs(Netlink *drv,
                               struct nl_msg *msg,
                               int (*valid_handler)(struct nl_msg *, void *),
                               void *valid_data) {
 return send_and_recv(drv, drv->socket, msg, valid_handler, valid_data);
}


int initNl80211(Netlink* nl, Wifi* w) {
  nl->socket = nl_socket_alloc();
  if (!nl->socket) { 
    printf("Failed to allocate netlink socket.\n");
    return -ENOMEM;
  }  

  nl_socket_set_buffer_size(nl->socket, 8192, 8192);

  if (genl_connect(nl->socket)) { 
    printf("Failed to connect to netlink socket.\n"); 
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
    return -ENOLINK;
  }
   
  nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
  if (nl->id < 0) {
    printf("Nl80211 interface not found.\n");
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
    return -ENOENT;
  }

  if (nl->nl_cb == NULL) {
     printf("Failed to allocate netlink callback.\n"); 
     nl_close(nl->socket);
     nl_socket_free(nl->socket);
     return ENOMEM;
  }

  nl->cb1 = nl_cb_alloc(NL_CB_DEFAULT);
  nl->cb2 = nl_cb_alloc(NL_CB_DEFAULT);
  nl->cb3 = nl_cb_alloc(NL_CB_DEFAULT);
  nl->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
  if ((!nl->cb1) || (!nl->cb2) || (!nl->cb3) || (!nl->nl_cb)) { 
     printf("Failed to allocate netlink callback.\n"); 
     nl_close(nl->socket);
     nl_socket_free(nl->socket);
     return ENOMEM;
  }

  nl_cb_set(nl->cb1, NL_CB_VALID , NL_CB_CUSTOM, getWifiIndex_callback, w);
  nl_cb_set(nl->cb1, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &(nl->result1));
  nl_cb_set(nl->cb2, NL_CB_VALID , NL_CB_CUSTOM, getWifiInfo_callback, w);
  nl_cb_set(nl->cb2, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &(nl->result2));
  nl_cb_set(nl->cb3, NL_CB_VALID , NL_CB_CUSTOM, getWifiFreq_callback, w);
  nl_cb_set(nl->cb3, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &(nl->result3));
  
  return nl->id;
}


static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
  int *ret = arg;
  *ret = err->error;
  return NL_SKIP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
  int *ret = arg;
  *ret = 0;
  return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
  int *err = arg;
  *err = 0;
  return NL_STOP;
}

int getWifiIndex_callback(struct nl_msg *msg, void *arg) {
 
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];

  //nl_msg_dump(msg, stdout);

  nla_parse(tb_msg,
            NL80211_ATTR_MAX,
            genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0),
            NULL);

  if (tb_msg[NL80211_ATTR_IFNAME]) {
    printf("getWifiIndex_callback - name of itf : %s\n", nla_get_string(tb_msg[NL80211_ATTR_IFNAME]));
    // If interface found doesn't have the correct name, skip
    if(strcmp( ((Wifi*)arg)->ifname, nla_get_string(tb_msg[NL80211_ATTR_IFNAME]) ))
      return NL_SKIP;
  }

/* Get interface index */
  if (tb_msg[NL80211_ATTR_IFINDEX]) {
    ((Wifi*)arg)->ifindex = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
  }

/* Get current frequency */
  if (tb_msg[NL80211_ATTR_WIPHY_FREQ]) {
    printf("getWifiIndex_callback - freq : %u\n", nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]));
    ((Wifi*)arg)->freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);
  }

  return NL_SKIP;
}


int getWifiInfo_callback(struct nl_msg *msg, void *arg) {
  struct nlattr *tb[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
  struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
  //nl_msg_dump(msg, stdout);

  nla_parse(tb,
            NL80211_ATTR_MAX,
            genlmsg_attrdata(gnlh, 0),
            genlmsg_attrlen(gnlh, 0),
            NULL);
  
  if (!tb[NL80211_ATTR_STA_INFO]) {
    printf("Station stats missing"); return NL_SKIP;
  }

  if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                       tb[NL80211_ATTR_STA_INFO], stats_policy)) {
    printf("Failed to parse nested attributes for station"); return NL_SKIP;
  }

  if (sinfo[NL80211_STA_INFO_TX_BITRATE]) {  
    if (nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX,
                         sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
      printf("Failed to parse nested rate attributes for station"); } 
    else {
      if (rinfo[NL80211_RATE_INFO_MCS]) {
        ((Wifi*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
        printf("getWifiInfo_callback - mcs : %u\n", nla_get_u32(rinfo[NL80211_RATE_INFO_MCS]));
      }
      if (rinfo[NL80211_RATE_INFO_BITRATE32]) {
        ((Wifi*)arg)->txrate = nla_get_u32(rinfo[NL80211_RATE_INFO_BITRATE32]);
      } 
      if (rinfo[NL80211_RATE_INFO_VHT_MCS]) {
        ((Wifi*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_MCS]);
      }
      if (rinfo[NL80211_RATE_INFO_VHT_NSS]) {
        ((Wifi*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);
      }
    }
  }

  if (sinfo[NL80211_STA_INFO_TX_FAILED]) {
    ((Wifi*)arg)->txfailed = nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);
  }

  return NL_SKIP;
}

int bss_info_handler(struct nl_msg *msg, void *arg) {
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_BSSID] = { },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
		[NL80211_BSS_STATUS] = { .type = NLA_U32 },
	};
	struct link_result *result = arg;
	char mac_addr[20];

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS]) {
		printf("bss info missing!\n");
		return NL_SKIP;
	}
	if (nla_parse_nested(bss, NL80211_BSS_MAX,
			     tb[NL80211_ATTR_BSS],
			     bss_policy)) {
		printf("failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	if (!bss[NL80211_BSS_BSSID])
		return NL_SKIP;

	if (!bss[NL80211_BSS_STATUS])
		return NL_SKIP;

	mac_addr_n2a(mac_addr, nla_data(bss[NL80211_BSS_BSSID]));

	switch (nla_get_u32(bss[NL80211_BSS_STATUS])) {
	case NL80211_BSS_STATUS_ASSOCIATED:
		printf("Connected to %s \n", mac_addr);
		break;
	case NL80211_BSS_STATUS_AUTHENTICATED:
		printf("Authenticated with %s \n", mac_addr);
		return NL_SKIP;
	case NL80211_BSS_STATUS_IBSS_JOINED:
		printf("Joined IBSS %s \n", mac_addr);
		break;
	default:
		return NL_SKIP;
	}

	result->anything_found = true;

/*
	if (bss[NL80211_BSS_INFORMATION_ELEMENTS])
		print_ies(nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
			  nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
			  false, PRINT_LINK);
*/

	if (bss[NL80211_BSS_FREQUENCY])
		printf("\tfreq: %d\n",
			nla_get_u32(bss[NL80211_BSS_FREQUENCY]));

	if (nla_get_u32(bss[NL80211_BSS_STATUS]) != NL80211_BSS_STATUS_ASSOCIATED)
		return NL_SKIP;

	/* only in the assoc case do we want more info from station get */
	result->link_found = true;
	memcpy(result->bssid, nla_data(bss[NL80211_BSS_BSSID]), 6);
	return NL_SKIP;
}

int protocol_feature_handler(struct nl_msg *msg, void *arg) {
printf("protocol_feature_handler\n");
  unsigned int *feat = arg;

  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]) {
    *feat = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);
    printf("protocol_callback feat : %u\n", *feat);
  }
  return NL_SKIP;
}


unsigned int get_nl80211_protocol_features(Netlink *nl, Wifi* w) {
  unsigned int feat = 0;
  struct nl_msg *msg;


  msg = nlmsg_alloc();

  if (!msg) {
    printf("Failed to allocate netlink message");
    return -1;
  }
  
  if(!nl80211_cmd(nl, msg, 0, NL80211_CMD_GET_PROTOCOL_FEATURES)) {
    nlmsg_free(msg);
    return -1;
  } 

  nla_put_u32(msg, NL80211_ATTR_IFINDEX, w->ifindex); 

  send_and_recv_msgs(nl, msg, protocol_feature_handler, &feat);

  return feat;
}


int getWifiFreq_callback(struct nl_msg *msg, void *arg) {
  struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
  struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];
  struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
  struct nlattr *nl_band;
  int rem_band;
  static int last_band = -1;

  nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

/* Get current freq */
  if(tb_msg[NL80211_ATTR_WIPHY_FREQ])
     ((Wifi*)arg)->freq = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY_FREQ]);

  if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
    return NL_SKIP;

  nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
    if (last_band != nl_band->nla_type) {
      printf("\tBand %d:\n", nl_band->nla_type + 1);
      printf("\tFreq %d:\n", ((Wifi*)arg)->freq);
    }

    last_band = nl_band->nla_type;

    nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band), nla_len(nl_band), NULL);

/* Get results on correct band (2.4 or 5Ghz, check if frequency > 5Ghz) */
    if( ((Wifi*)arg)->freq > 0 && nl_band->nla_type + 1 == ( ((Wifi*)arg)->freq >= 5000 ? 2 : 1) ) {
      if (tb_band[NL80211_BAND_ATTR_HT_CAPA] && tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) {
((Wifi*)arg)->ht_cap =  nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
 printf("\tHT CAP %d:\n", ((Wifi*)arg)->ht_cap);
        if(((Wifi*)arg)->mcs < 0 && nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) == 16) 
          ((Wifi*)arg)->mcs = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]);
      printf("\tMCS HT %d:\n", ((Wifi*)arg)->mcs);
      }
      if (tb_band[NL80211_BAND_ATTR_VHT_CAPA] && tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]) {
((Wifi*)arg)->vht_cap =  nla_get_u16(tb_band[NL80211_BAND_ATTR_VHT_CAPA]);
 printf("\tVHT CAP %d:\n", ((Wifi*)arg)->vht_cap);
        if(((Wifi*)arg)->mcs < 0) 
          ((Wifi*)arg)->mcs = nla_get_u16(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
      printf("\tMCS VHT %d:\n", ((Wifi*)arg)->mcs);

      }
    }
  }
  
  return NL_SKIP;
}

int getWifiInterface(Netlink* nl, Wifi* w) {
  nl->result1 = 1;

/* Get itf ID */
    
  struct nl_msg* msg1 = nlmsg_alloc();
  if (!msg1) {
    printf("Failed to allocate netlink message.\n");
    return -1;
  }
 
  if(!nl80211_cmd(nl, msg1, NLM_F_DUMP, NL80211_CMD_GET_INTERFACE)) {
    nlmsg_free(msg1);
    printf("Init of message for netlink cmd NL80211_CMD_GET_INTERFACE failed");
    return -1;
  } 

  nl_send_auto(nl->socket, msg1);
  
  while (nl->result1 > 0) { nl_recvmsgs(nl->socket, nl->cb1); }
  nlmsg_free(msg1);

  if (w->ifindex < 0) { return -1; }

  return 0;
}

int getWifiStatus(Netlink* nl, Wifi* w) {
  nl->result2 = 1;
  nl->result3 = 1;

/* Get station info */

  struct nl_msg* msg2 = nlmsg_alloc();

  if (!msg2) {
    printf("Failed to allocate netlink message.\n");
    return -1;
  }
  
  if(!nl80211_cmd(nl, msg2, NLM_F_DUMP, NL80211_CMD_GET_STATION)) { 
    nlmsg_free(msg2);
    printf("Init of message for netlink cmd NL80211_CMD_GET_STATION failed");
    return -1;
  } 
              
  nla_put_u32(msg2, NL80211_ATTR_IFINDEX, w->ifindex); 
  nl_send_auto(nl->socket, msg2); 
  while (nl->result2 > 0) { nl_recvmsgs(nl->socket, nl->cb2); }
  nlmsg_free(msg2);

/* Get protocol and freq/rate info */
   
  unsigned int feat;
  int flags = 0;

  feat = get_nl80211_protocol_features(nl, w);
  printf("get_nl80211_protocol_features: feat %d\n", feat);
  if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
    flags = NLM_F_DUMP;


  struct nl_msg* msg3 = nlmsg_alloc();

  if (!msg3) {
    printf("Failed to allocate netlink message.\n");
    return -1;
  }
  
printf("get wiphy :\n");
  if(!nl80211_cmd(nl, msg3, flags, NL80211_CMD_GET_WIPHY) || nla_put_flag(msg3, NL80211_ATTR_SPLIT_WIPHY_DUMP)) {
    nlmsg_free(msg3);
    printf("Init of message for netlink cmd NL80211_CMD_GET_WIPHY failed");
    return -1;
  } 
              
  nla_put_u32(msg3, NL80211_ATTR_IFINDEX, w->ifindex); 
  nl_send_auto(nl->socket, msg3); 
  while (nl->result3 > 0) { nl_recvmsgs(nl->socket, nl->cb3); }
  nlmsg_free(msg3);


  struct nl_msg *msg4;

  msg4 = nlmsg_alloc();

  if (!msg4) {
    printf("Failed to allocate netlink message");
    return -1;
  }
  
  if(!nl80211_cmd(nl, msg4, NLM_F_DUMP, NL80211_CMD_GET_SCAN)) {
    nlmsg_free(msg4);
    return -1;
  } 

  struct link_result bss_info;

  nla_put_u32(msg4, NL80211_ATTR_IFINDEX, w->ifindex); 

  send_and_recv_msgs(nl, msg4, bss_info_handler, &bss_info);

  return 0;
}

int getNl80211Info(struct station_info *sta_info, const char *itf_name) {
  Netlink nl;
  Wifi w;

  w.vht_cap = 0;
  w.ht_cap = 0;
  w.mcs = -1;
  w.nss = -1;
  w.freq = -1;

  strcpy(w.ifname, itf_name);

  nl.id = initNl80211(&nl, &w);
  if (nl.id < 0) {
    printf("Error initializing netlink 802.11");
    return -1;
  }

  if(getWifiInterface(&nl, &w) < 0) {
    printf("Error getting info on interface");
    return -1;
  }  
  if(getWifiStatus(&nl, &w) < 0) {
    printf("Error getting info on attributes");
    return -1;
  } 
 
  sta_info->rate = (w.txrate > 0) ? w.txrate*100 : 0;
  
  if(w.freq < 0) {
    sta_info->primChannel = w.freq;
    sta_info->band = NET80211_BAND_EMPTY;
  }
  else {
    if (w.freq >= 5000) {
      sta_info->primChannel = (w.freq-5000)/5;
      sta_info->band = NET80211_BAND_5GHZ;
    }
    else {
      sta_info->primChannel = (w.freq - 2407)/5;
      sta_info->band = NET80211_BAND_2_4GHZ;
    }
  }

 if (sta_info->band == NET80211_BAND_5GHZ) {
    if (w.vht_cap)
      sta_info->l802_11Modes = NET80211_WIRELESS_MODE_AC;
    else if (w.ht_cap)
      sta_info->l802_11Modes = NET80211_WIRELESS_MODE_N;
    else
      sta_info->l802_11Modes = NET80211_WIRELESS_MODE_A;
  }
  else {
    if (w.ht_cap)
      sta_info->l802_11Modes = NET80211_WIRELESS_MODE_N;
    else
      sta_info->l802_11Modes = NET80211_WIRELESS_MODE_G;
  }
 
  if(sta_info->ErrorsSent < 0) sta_info->ErrorsSent = w.txfailed;

  if(w.nss < 0) {
    if(w.mcs < 8)
      w.nss = 1;
    else if(w.mcs >= 8 && w.mcs < 16)
      w.nss = 2;
    else
      w.nss = 3;
  }

  printf("Interface: %s | txrate: %d MBit/s | txfailed: %d \
| freq: %d | MCS: %d | NSS: %d | VHT_CAP: %d | HT_CAP: %d\n",
           w.ifname, w.txrate, w.txfailed, w.freq, w.mcs, w.nss, w.vht_cap, w.ht_cap);

  nl_cb_put(nl.cb1);
  nl_cb_put(nl.cb2);
  nl_cb_put(nl.cb3);
  nl_cb_put(nl.nl_cb);
  nl_close(nl.socket);
  nl_socket_free(nl.socket);
  return 0;
}

int main() {
  struct station_info *itf_info = malloc(sizeof(struct station_info));
  getNl80211Info(itf_info, "wlp3s0");
  return 0;
}
