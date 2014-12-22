#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/if.h>
#include "setbssid.h"

//copy this from iw

#include <netlink/attr.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <linux/nl80211.h>

#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <netlink/genl/family.h>
#include <netlink/msg.h>


#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

static int expectedId;

static int get_addr(struct nlattr *tb[], uint8_t **addr)
{
	if (tb[NL80211_ATTR_MAC] == NULL)
		return -1;
	*addr = nla_data(tb[NL80211_ATTR_MAC]);
	return 0;
}



static int nlCallback(struct nl_msg* msg, void* arg)
{
    struct nlmsghdr* ret_hdr = nlmsg_hdr(msg);
    struct nlattr *tb[NL80211_ATTR_MAX + 1];

    if (ret_hdr->nlmsg_type != expectedId)
    {
        // what is this??
        return NL_STOP;
    }

    struct genlmsghdr *gnlh = (struct genlmsghdr*) nlmsg_data(ret_hdr);

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    uint8_t *addr;

	switch(gnlh->cmd) {
	case NL80211_CMD_SET_INTERFACE:
		if (get_addr(tb, &addr) < 0)
			printf("New station: no MAC\n");
		else
			printf("New station: "MACSTR"\n", MAC2STR(addr));
		break;
}
}
static int cmd_size;

extern struct cmd __start___cmd;
extern struct cmd __stop___cmd;

#define for_each_cmd(_cmd)					\
	for (_cmd = &__start___cmd; _cmd < &__stop___cmd;		\
	     _cmd = (const struct cmd *)((char *)_cmd + cmd_size))

int main(int argc, char** argv)
{
	enum nl80211_commands cmd;
	struct nl_msg *msg;
    int ret;
    int flags;
    char *ifname;
    uint8_t mac_addr[ETH_ALEN];
    
    //allocate socket
    static struct nl_sock *sk = NULL;
    sk = nl_socket_alloc();
    if (sk == NULL) {
		print_err("Unable to allocate Netlink socket\n");
		exit(EXIT_FAILURE);
	}

    //connect to generic netlink
    genl_connect(sk);

    //find the nl80211 driver ID
    expectedId = genl_ctrl_resolve(sk, "nl80211");

    //attach a callback
    ret = nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
            nlCallback, NULL);
    if (ret < 0) {
		printf("Unable to register callback %d\n", ret);
		return -1;
	}

    //allocate a message
    msg = nlmsg_alloc();
    if (!msg){return -1;}

    cmd = NL80211_CMD_SET_INTERFACE;

     printf("please input the mac :\n");  
    scanf("%s",mac_addr); 
    flags = 0;	

    MAC2STR(mac_addr);

    // setup the message
    genlmsg_put(msg, 0, 0, expectedId, 0, flags, cmd, 0);

    //add message attributes
    NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, mac_addr);

    //send the messge (this frees it)
    ret = nl_send_auto_complete(sk, msg);
	if (ret < 0) {
		if (ret == -1) {
			nlmsg_free(msg);
			return -1;
		}

		printf("Cannot send_auto_complete!\n");
	}



    //block for message to return
    ret = nl_recvmsgs_default(sk);
	msg = NULL;
	if (ret){
    	nla_put_failure:
	nlmsg_free(msg);
	//printf(0, "nl80211: Failed to execute CMD %d on " "%s: error =%d:%s", cmd, ifname, ret, strerror(-ret));
		
	}
return 0;
}

