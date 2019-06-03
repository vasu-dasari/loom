%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. Jan 2018 8:48 PM
%%%-------------------------------------------------------------------
-module(discovery).
-author("vdasari").

-behavior(gen_lldp).

-include_lib("lldp/include/lldp_api.hrl").
-include_lib("kernel/include/inet.hrl").

-include_lib("loom/include/logger.hrl").
-include_lib("loom/include/loom_api.hrl").

%% API

-export([init/1, handle_message/2, terminate/2, notify/4, info/2]).

-export([start/1,stop/1,neighbor/2,register/1,unregister/1,notify/1,info/1]).

-define(version(State),     (State#state.switch_info)#switch_info_t.version).
-define(switch_id(State),   (State#state.switch_info)#switch_info_t.switch_id).
-define(datapath_id(State), (State#state.switch_info)#switch_info_t.datapath_id).
-define(ip_address(State), (State#state.switch_info)#switch_info_t.ip_addr).

-record(state, {
    switch_id,
    datapath_id,
    ip_address,
    version,
    switch_info = #switch_info_t{} :: #switch_info_t{},
    chassis_id = <<>>,
    sys_name = <<>>,
    sys_descr = <<>>,
    if_map = #{},
    port_map = #{}
}).

-record(lldp_loom_intf_t, {
    if_name,
    if_index
}).

%%%===================================================================
%%% Discovery module APIs
%%%===================================================================

start(SwitchInfo) ->
    ProcName = loom_utils:proc_name(?MODULE,SwitchInfo),
    {ok, ChildState} = init(SwitchInfo),
    loom_handler_sup:start_child(
        ProcName,
        loom_handler_sup:childspec(ProcName, gen_lldp, [ProcName, ?MODULE, ChildState])
    ).

stop(Pid) ->
    loom_handler_sup:stop_child(Pid).

info(SwitchKey) ->
    io:format("~s", [gen_lldp:info(loom_utils:proc_name(?MODULE, SwitchKey), {info,dashboard})]).

neighbor(SwitchKey, Key) ->
    ProcName = loom_utils:proc_name(?MODULE, SwitchKey),
    case loom_logic:get_switch(SwitchKey) of
        #switch_info_t{} when is_integer(Key) ->
            lldp_manager:get_neighbors(ProcName, {if_index, Key});
        #switch_info_t{} = SwitchInfo when is_list(Key) ->
            lldp_manager:get_neighbors(loom_utils:proc_name(?MODULE, SwitchInfo), {chassis, Key});
        #switch_info_t{} = SwitchInfo ->
            lldp_manager:get_neighbors(loom_utils:proc_name(?MODULE, SwitchInfo), Key);
        _ ->
            not_found
    end.

register(Pid) ->
    pg2:create(loom_topology),
    pg2:join(loom_topology, Pid).

unregister(Pid) ->
    pg2:leave(loom_topology, Pid).

notify(Message) ->
    case pg2:get_local_members(loom_topology) of
        {error, _} ->
            ok;
        Pids ->
            [Pid ! {?MODULE, Message} || Pid <- Pids]
    end.

%%%===================================================================
%%% gen_lldp callbacks
%%%===================================================================

init(
        #switch_info_t{
            switch_id = _SwitchId,
            datapath_id = _DpId
        } = SwitchInfo) ->
    {ok, #state{
        switch_info = SwitchInfo
    }}.

handle_message(started, State) ->
    loom_logic:filter(add, ?datapath_id(State),
        #loom_pkt_desc_t{
            dst_mac = inet_utils:convert_mac(to_binary, ?LldpMac),
            ether_type = ?LldpEtherType
        }, self()),

    Request = of_msg_lib:flow_add(?version(State),
        [   %% Matches: LLDP Destination MAC
            {eth_dst, inet_utils:convert_mac(to_binary, ?LldpMac)}
        ],
        [{apply_actions, [          %% Actions: Send such a packet to controller
            {output, 'controller', no_buffer}
        ]}],
        [{priority, 16#ffff}]       %% Priority of 16#ffff
    ),
    loom_logic:send(?switch_id(State), Request),

    loom_logic:filter(add, ?datapath_id(State), port_status, self()),

    State1 = populate_system_info(State),

    {ok, scan_ifs(State1)};

handle_message({tx_packet, IfName, TxData}, #state{if_map = IfMap} = State) ->
    #{IfName := #lldp_loom_intf_t{if_index = IfIndex}} = IfMap,
    loom_logic:send(?switch_id(State), [
        send_packet, TxData, 'controller', [{output, IfIndex, no_buffer}]
    ]),
    {ok, State};

handle_message({rx_packet, InPort, _, Data} , #state{port_map = PortMap} = State) ->
    case maps:get(InPort, PortMap, []) of
        [] ->
            ok;
        #lldp_loom_intf_t{if_name = IfName} ->
            gen_lldp:rx_packet(IfName, Data)
    end,
    {ok, State};

handle_message({notify, port_status, _InPort, add, PortDesc}, State) ->
    {ok, enable_lldp(proplists:get_value(name, PortDesc), PortDesc, State)};

handle_message({notify, port_status, _InPort, delete, PortDesc}, State) ->
    {ok, disable_lldp(proplists:get_value(name, PortDesc), PortDesc, State)};

handle_message({notify, port_status, InPort, _Reason, PortDesc}, State) when is_integer(InPort) ->
    IfName = proplists:get_value(name, PortDesc),
    gen_lldp:interface(update, IfName, loom_utils:is_link_up(PortDesc)),
    {ok, State};

handle_message(Message, State) ->
    ?INFO("Message: ~p", [Message]),
    {ok, State}.

notify(Op, IfName, EntityInfo, #state{if_map = IfMap} = State) ->
    ?DEBUG("~p Neighbor on ~p~n~s", [Op,IfName, lldp_utils:record_to_proplist(to_str, EntityInfo)]),
    #{IfName := #lldp_loom_intf_t{if_index = IfIndex}} = IfMap,
    notify({Op, ?datapath_id(State), IfName, IfIndex, EntityInfo}),
    {ok, State}.

info(_Request, _State) ->
    {ok, "Hello World"}.

terminate(_Reason, State) ->
    loom_logic:filter(delete, ?datapath_id(State),
        #loom_pkt_desc_t{
            dst_mac = inet_utils:convert_mac(to_binary, ?LldpMac),
            ether_type = ?LldpEtherType
        }, self()),

    Request = of_msg_lib:flow_delete(?version(State),
        [
            %% Matches: LLDP Destination MAC
            {eth_dst, inet_utils:convert_mac(to_binary, ?LldpMac)}
        ],
        [{priority, 16#ffff}]       %% Priority of 16#ffff
    ),
    loom_logic:send(?switch_id(State), Request),

    loom_logic:filter(delete, ?datapath_id(State), port_status, self()),

    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
populate_system_info(State) ->
    {features_reply, _, FeaturesReply} = loom_logic:sync_send(?switch_id(State), get_features),
    ChassisId = proplists:get_value(datapath_mac, FeaturesReply),

    SystemName = case inet:gethostbyaddr(?ip_address(State)) of
        {ok,#hostent{h_name = Hostname}} ->
            Hostname;
        _ ->
            inet_utils:convert_ip(to_string, ?ip_address(State))
    end,

    {desc_reply, _, DescReply} = loom_logic:sync_send(?switch_id(State), get_description),
    SysDescr = io_lib:format("Datapath Id ~s, ~s ~s, ~s, S/N ~s", [
        ?datapath_id(State),
        binary_to_list(proplists:get_value(hw_desc, DescReply, <<>>)),
        binary_to_list(proplists:get_value(sw_desc, DescReply, <<>>)),
        binary_to_list(proplists:get_value(mfr_desc, DescReply, <<>>)),
        binary_to_list(proplists:get_value(serial_num, DescReply, <<>>))
    ]),

    State#state{
        chassis_id = ChassisId,
        sys_name = list_to_binary(SystemName),
        sys_descr = list_to_binary(lists:flatten(SysDescr))
    }.

scan_ifs(#state{switch_info = #switch_info_t{}} = State) ->
    {port_desc_reply, _, [{flags,_}, {ports,PortList}]} =
        loom_logic:sync_send(?switch_id(State), get_port_descriptions),
    lists:foldl(fun
        (PropList, Acc) ->
            case proplists:get_value(port_no, PropList) /= local of
                true ->
                    enable_lldp(proplists:get_value(name, PropList), PropList, Acc);
                _ ->
                    Acc
            end
    end, State, PortList).

enable_lldp(IfName, IfPropList, #state{if_map = IfMap, port_map = PortMap} = State) ->
    PortMac = inet_utils:convert_mac(to_binary, proplists:get_value(hw_addr, IfPropList, 0)),
    IfIndex = proplists:get_value(port_no, IfPropList),
    IfInfo = #lldp_entity_t{
        src_mac = PortMac,
        chassis_id = State#state.chassis_id,
        port_id = (IfName),
        sys_descr = State#state.sys_descr,
        sys_name = State#state.sys_name,
        if_index = IfIndex,
        mgmt_ip = PortMac,
        if_state = loom_utils:is_link_up(IfPropList)
    },
    gen_lldp:interface(create, IfName, IfInfo),
    CelloIfInfo = #lldp_loom_intf_t{if_name = IfName, if_index = IfIndex},
    State#state{
        if_map = IfMap#{IfName => CelloIfInfo},
        port_map = PortMap#{IfIndex => CelloIfInfo}
    }.

disable_lldp(IfName, IfPropList, #state{if_map = IfMap, port_map = PortMap} = State) ->
    IfIndex = proplists:get_value(port_no, IfPropList),
    case maps:get(IfName, IfMap, []) of
        #lldp_loom_intf_t{} ->
            gen_lldp:interface(destroy, IfName, '_'),
            State#state{
                if_map = maps:remove(IfName, IfMap),
                port_map = maps:remove(IfIndex, PortMap)
            };
        _ ->
            State
    end.