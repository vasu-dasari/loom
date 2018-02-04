%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 29. Jan 2018 9:19 AM
%%%-------------------------------------------------------------------
-author("vdasari").

-record(loom_pkt_desc_t, {
    src_mac = dont_care,
    dst_mac = dont_care,
    ether_type = dont_care,
    vlan_id = dont_care
}).

-record(loom_notification_t, {
    key :: #loom_pkt_desc_t{},
    dp_list = #{}
}).

-record(loom_event_t, {
    key :: atom(),
    dp_list = #{}
}).