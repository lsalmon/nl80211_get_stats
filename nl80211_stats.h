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

/** Private command structure */
struct eth_priv_cmd {
    /** Command buffer pointer */
        unsigned long long buf;
    /** buffer updated by driver */
        int used_len;
    /** buffer sent by application */
        int total_len;
} __ATTRIB_PACK__;

/** data structure for cmd getdatarate */
struct eth_priv_data_rate {
    /** Tx data rate */
        unsigned int tx_data_rate;
    /** Rx data rate */
        unsigned int rx_data_rate;

    /** Tx channel bandwidth */
        unsigned int tx_bw;
    /** Tx guard interval */
        unsigned int tx_gi;
    /** Rx channel bandwidth */
        unsigned int rx_bw;
    /** Rx guard interval */
        unsigned int rx_gi;
    /** MCS index */
        unsigned int tx_mcs_index;
        unsigned int rx_mcs_index;
    /** NSS */
        unsigned int tx_nss;
        unsigned int rx_nss;
        /* LG rate: 0, HT rate: 1, VHT rate: 2 */
        unsigned int tx_rate_format;
        unsigned int rx_rate_format;
};


/** data structure for cmd getlog */
struct eth_priv_get_log {
    /** Multicast transmitted frame count */
        unsigned int mcast_tx_frame;
    /** Failure count */
        unsigned int failed;
    /** Retry count */
        unsigned int retry;
    /** Multi entry count */
        unsigned int multi_retry;
    /** Duplicate frame count */
        unsigned int frame_dup;
    /** RTS success count */
        unsigned int rts_success;
    /** RTS failure count */
        unsigned int rts_failure;
    /** Ack failure count */
        unsigned int ack_failure;
    /** Rx fragmentation count */
        unsigned int rx_frag;
    /** Multicast Tx frame count */
        unsigned int mcast_rx_frame;
    /** FCS error count */
        unsigned int fcs_error;
    /** Tx frame count */
        unsigned int tx_frame;
    /** WEP ICV error count */
        unsigned int wep_icv_error[4];
    /** beacon recv count */
        unsigned int bcn_rcv_cnt;
    /** beacon miss count */
        unsigned int bcn_miss_cnt;
    /** Tx frag count */
        unsigned int tx_frag_cnt;
    /** Qos Tx frag count */
        unsigned int qos_tx_frag_cnt[8];
    /** Qos failed count */
        unsigned int qos_failed_cnt[8];
    /** Qos retry count */
        unsigned int qos_retry_cnt[8];
    /** Qos multi retry count */
        unsigned int qos_multi_retry_cnt[8];
    /** Qos frame dup count */
        unsigned int qos_frm_dup_cnt[8];
    /** Qos rts success count */
        unsigned int qos_rts_suc_cnt[8];
    /** Qos rts failure count */
        unsigned int qos_rts_failure_cnt[8];
    /** Qos ack failure count */
        unsigned int qos_ack_failure_cnt[8];
    /** Qos Rx frag count */
        unsigned int qos_rx_frag_cnt[8];
    /** Qos Tx frame count */
        unsigned int qos_tx_frm_cnt[8];
    /** Qos discarded frame count */
        unsigned int qos_discarded_frm_cnt[8];
    /** Qos mpdus Rx count */
        unsigned int qos_mpdus_rx_cnt[8];
    /** Qos retry rx count */
        unsigned int qos_retries_rx_cnt[8];
    /** CMACICV errors count */
        unsigned int cmacicv_errors;
    /** CMAC replays count */
        unsigned int cmac_replays;
    /** mgmt CCMP replays count */
        unsigned int mgmt_ccmp_replays;
    /** TKIP ICV errors count */
        unsigned int tkipicv_errors;
    /** TKIP replays count */
        unsigned int tkip_replays;
    /** CCMP decrypt errors count */
        unsigned int ccmp_decrypt_errors;
    /** CCMP replays count */
        unsigned int ccmp_replays;
    /** Tx amsdu count */
        unsigned int tx_amsdu_cnt;
    /** failed amsdu count */
        unsigned int failed_amsdu_cnt;
    /** retry amsdu count */
        unsigned int retry_amsdu_cnt;
    /** multi-retry amsdu count */
        unsigned int multi_retry_amsdu_cnt;
    /** Tx octets in amsdu count */
        unsigned long long tx_octets_in_amsdu_cnt;
    /** amsdu ack failure count */
        unsigned int amsdu_ack_failure_cnt;
    /** Rx amsdu count */
        unsigned int rx_amsdu_cnt;
    /** Rx octets in amsdu count */
        unsigned long long rx_octets_in_amsdu_cnt;
    /** Tx ampdu count */
        unsigned int tx_ampdu_cnt;
    /** tx mpdus in ampdu count */
        unsigned int tx_mpdus_in_ampdu_cnt;
    /** tx octets in ampdu count */
        unsigned long long tx_octets_in_ampdu_cnt;
    /** ampdu Rx count */
        unsigned int ampdu_rx_cnt;
    /** mpdu in Rx ampdu count */
        unsigned int mpdu_in_rx_ampdu_cnt;
    /** Rx octets ampdu count */
        unsigned long long rx_octets_in_ampdu_cnt;
    /** ampdu delimiter CRC error count */
        unsigned int ampdu_delimiter_crc_error_cnt;
};

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
  struct nl_cb *cb1, *cb2, *cb3, *tmp_cb, *nl_cb;
  int result1, result2, result3, tmp_result;
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

struct station_info {
  int rate;
  int primChannel;
  int band;
  int l802_11Modes;
  int ErrorsSent;
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

int bss_info_handler(struct nl_msg *msg, void *arg);
int protocol_feature_handler(struct nl_msg *msg, void *arg);
int getWifiIndex_callback(struct nl_msg *msg, void *arg);
int getWifiInfo_callback(struct nl_msg *msg, void *arg);
int getWifiFreq_callback(struct nl_msg *msg, void *arg);
int getWifiStatus(Netlink* nl, Wifi* w);

int getWifiInterface(Netlink* nl, Wifi* w);
int getNl80211Info(struct station_info *sta_info, const char *itf_name); 
