#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>              
#include <linux/netlink.h>    //lots of netlink functions
#include <netlink/genl/genl.h>  //genl_connect, genlmsg_put
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>  //genl_ctrl_resolve
#include <linux/nl80211.h>      //NL80211 definitions
#include <linux/if_ether.h>  // ETH_ALEN def


#define IEEE80211_HT_MCS_MASK_LEN  10
#define nl_handle nl_sock


struct ieee80211_vht_mcs_info {
        __le16 rx_mcs_map;
        __le16 rx_highest;
        __le16 tx_mcs_map;
        __le16 tx_highest;
} __attribute__((packed));


struct ieee80211_vht_cap {
        __le32 vht_cap_info;
        struct ieee80211_vht_mcs_info supp_mcs;
} __attribute__((packed));


struct ieee80211_mcs_info {
        uint8_t rx_mask[IEEE80211_HT_MCS_MASK_LEN];
        __le16 rx_highest;
        uint8_t tx_params;
        uint8_t reserved[3];
} __attribute__((packed));


typedef struct {
  int id;
  struct nl_sock* socket;
  struct nl_cb *nl_cb;
} Netlink; 

typedef struct {
  char ifname[64];
  int ifindex;
  int txrate;
  int txfailed;
  int chan;
  int mcs;
  int nss;
  int vht_cap;
  int ht_cap;
  unsigned int freq;
} Wifi;

typedef enum {
  NET80211_BAND_EMPTY,
  NET80211_BAND_2_4GHZ,
  NET80211_BAND_5GHZ
} NET80211_BAND;

typedef enum {
  NET80211_WIRELESS_MODE_A,
  NET80211_WIRELESS_MODE_B,
  NET80211_WIRELESS_MODE_G,
  NET80211_WIRELESS_MODE_N,
  NET80211_WIRELESS_MODE_AC
} NET80211_WIRELESS;

int legacy_data_rates_b [] = { 1, 2, 5.5, 11 };
int legacy_data_rates_ag [] = { 6, 9, 12, 18, 24, 36, 48, 54 };

struct station_info {
  int rate;
  int primChannel;
  int band;
  int l802_11Modes;
  int ErrorsSent;
};

struct bss_info {
        uint8_t bssid[8];
        bool link_found;
        bool anything_found;
};

int initNl80211(Netlink* nl, Wifi* w);
static int send_and_recv(Netlink *drv,
                          struct nl_sock *nl_socket, struct nl_msg *msg,
                          int (*valid_handler)(struct nl_msg *, void *),
                          void *valid_data);
static int send_and_recv_msgs(Netlink *drv,
                               struct nl_msg *msg,
                               int (*valid_handler)(struct nl_msg *, void *),
                               void *valid_data);

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
static int finish_handler(struct nl_msg *msg, void *arg);
static int ack_handler(struct nl_msg *msg, void *arg);

int bss_info_callback(struct nl_msg *msg, void *arg);
int protocol_feature_callback(struct nl_msg *msg, void *arg);
int get_windex_callback(struct nl_msg *msg, void *arg);
int get_winfo_callback(struct nl_msg *msg, void *arg);
int get_wfreq_callback(struct nl_msg *msg, void *arg);

int getNl80211Status(Netlink* nl, Wifi* w);
int getNl80211Interface(Netlink* nl, Wifi* w);
int getNl80211Info(struct station_info *sta_info, const char *itf_name); 
