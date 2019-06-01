%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 26. Jan 2018 10:19 PM
%%%-------------------------------------------------------------------
-module(loom_logic).
-author("vdasari").

-behaviour(gen_server).

-include_lib("loom/include/loom_api.hrl").
-include_lib("loom/include/logger.hrl").
-include_lib("of_protocol/include/of_protocol.hrl").

-include_lib("stdlib/include/ms_transform.hrl").

%% API
-export([start_link/0, start_link/2, stop/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([
    ofsh_init/6,
    ofsh_connect/6,
    ofsh_disconnect/2,
    ofsh_failover/0,
    ofsh_handle_message/2,
    ofsh_handle_error/2,
    ofsh_terminate/1,
    sync_send/2, send/2,
    connect/2,
    close_connection/1,

    subscribe/2]).

-export([get_switch/1, get_ports_info/1]).

-export([filter/4, find_loom/1, find_proc/2]).

-define(AppName, loom).
-define(EtsLoom, ets_loom).
-define(SERVER, ?MODULE).

-type switch_key() :: undefined | integer().

-record(loom_logic_state, {
    next_switch_key = 1 :: integer(),
    switches_table :: term(), % ets table
    default_switch :: switch_key()
}).

-record(state, {
    key,
    proc_name,
    datapath_id
}).

-define(wrapper(Type, SwitchKey, Args),
    case find_loom(SwitchKey) of
        not_found ->    ok;
        Proc ->         gen_server:Type(Proc, Args)
    end
).

-define(call(SwitchKey, Args), ?wrapper(call, SwitchKey, Args)).
-define(cast(SwitchKey, Args), ?wrapper(cast, SwitchKey, Args)).

%% ----------------------------------------------------------------------------
%% Callback API
%% ----------------------------------------------------------------------------

% These functions are called from loom_ofsh.erl.
-spec ofsh_init(handler_mode(), ipaddress(), datapath_id(), features(), of_version(), connection()) -> ok.
ofsh_init(active,IpAddress, DatapathId, _Features, Version, Connection) ->
    % new main connection
    ?INFO("Switch discvered at ~s, Datapath Id ~s, ~p~n", [
        inet_utils:convert_ip(to_string,IpAddress), DatapathId, ets:lookup(?EtsLoom, global)
    ]),
    SwitchInfo = #loom_switch_info_t{
        ip_addr = IpAddress,
        datapath_id = DatapathId,
        version = Version,
        connection = Connection
    },
    ok = gen_server:call(?MODULE, {init, SwitchInfo}),
    ok.

-spec ofsh_connect(handler_mode(), ipaddress(), datapath_id(), of_version(), connection(), auxid()) -> ok.
ofsh_connect(active, IpAddr, DatapathId, _Version, _Connection, AuxId) ->
    % new auxiliary connection - ignored
    ?INFO("new aux connection: ~p ~p ~p~n", [IpAddr, AuxId, DatapathId]),
    ok.

-spec ofsh_disconnect(auxid(), datapath_id()) -> ok.
ofsh_disconnect(AuxId, DatapathId) ->
    % closed auxiliary connection - ignored
    ?INFO("disconnect aux connection: ~p ~p~n", [AuxId, DatapathId]),
    ok.

-spec ofsh_failover() -> ok.
ofsh_failover() ->
    % ofs_handler failover - not implemented, ignored
    ?INFO("failover"),
    ok.

-spec ofsh_handle_message(datapath_id(), ofp_message()) -> ok.
ofsh_handle_message(DatapathId, {packet_in,0,PktDesc}) ->
    <<InPort:32>> = proplists:get_value(in_port, proplists:get_value(match, PktDesc, [])),
    try
        handle_packet_in(DatapathId, InPort, proplists:get_value(data, PktDesc))
    catch
        E:R  ->
            ?ERROR("E ~p, R ~p", [E,R])
    end,
    ok;

ofsh_handle_message(DatapathId, {port_status,0, [{reason, Reason}, {desc, PortDesc}] = PortStatus}) ->
    try
        handle_port_status(DatapathId, Reason, PortDesc)
    catch
        E:R  ->
            ?ERROR("E ~p, R ~p", [E,R])
    end,
    ?DEBUG("Port Status(~s):~n~p~n", [DatapathId, loom_utils:pretty_print(PortStatus)]),
    ok;
ofsh_handle_message(DatapathId, Msg) ->
    % process a message from the switch - print and ignore
    ?INFO("message in: ~p ~p~n", [DatapathId, Msg]),
    ok.

handle_port_status(DatapathId, Reason, PortDesc) ->
    InPort = proplists:get_value(port_no, PortDesc),
    case ets:select(?EtsLoom,
        ets:fun2ms(fun
            (#loom_notification_t{
                key = port_status,
                dp_list = P
            })  ->
                P
        end)) of
        [DpMap] ->
            ?DEBUG("~s: Event on ~p: Reason ~p, ~p~n~p", [DatapathId, InPort, Reason, PortDesc, DpMap]),
            case maps:get(DatapathId, DpMap, []) of
                [] ->
                    ok;
                Pid ->
                    ?DEBUG("Event on ~p: Reason ~p, ~p", [InPort, Reason, Pid]),
                    Pid ! {notify, port_status, InPort, Reason, PortDesc}
            end;
        _ ->
            ok
    end.

handle_packet_in(DatapathId, InPort, <<DstMac:6/bytes, SrcMac:6/bytes, EtherType:16, _/binary>> = PktData) ->
    ?DEBUG("Rx Packet on ~p~n~p", [InPort, EtherType]),
    PktDesc = #loom_pkt_desc_t{
        src_mac = SrcMac,
        dst_mac = DstMac,
        ether_type = EtherType
    },

    case ets:select(?EtsLoom,
        ets:fun2ms(fun
            (#loom_notification_t{
                key = K,
                dp_list = P
            }) when
                (is_record(K, loom_pkt_desc_t)),
                ((K#loom_pkt_desc_t.src_mac == dont_care) or (K#loom_pkt_desc_t.src_mac == PktDesc#loom_pkt_desc_t.src_mac)),
                ((K#loom_pkt_desc_t.dst_mac == dont_care) or (K#loom_pkt_desc_t.dst_mac == PktDesc#loom_pkt_desc_t.dst_mac)),
                ((K#loom_pkt_desc_t.ether_type== dont_care) or (K#loom_pkt_desc_t.ether_type == PktDesc#loom_pkt_desc_t.ether_type))
                ->
                P
        end)) of
        DpList when is_list(DpList) ->
            ?DEBUG("Rx Packet on ~p: ~p", [InPort, EtherType]),
            lists:foreach(fun
                (DpMap) ->
                    case maps:get(DatapathId, DpMap, []) of
                        [] ->
                            ok;
                        Pid ->
                            Pid ! {rx_packet, InPort, PktData}
                    end
            end, DpList);
        _ ->
            ok
    end.

-spec ofsh_handle_error(datapath_id(), error_reason()) -> ok.
ofsh_handle_error(DatapathId, Reason) ->
    % Error on connection - print and ignore
    ?INFO("error in: ~p ~p~n", [DatapathId, Reason]),
    ok.

-spec ofsh_terminate(datapath_id()) -> ok.
ofsh_terminate(DatapathId) ->
    % lost the main connection
    ?INFO("Switch ~s is disconnected: ~p", [DatapathId, find_loom(DatapathId)]),
    ok = gen_server:call(?MODULE, {stop, DatapathId}).

%% ----------------------------------------------------------------------------
%% Utility API
%% ----------------------------------------------------------------------------

%% @doc
%% Send ``Msg'' to the switch connected from ``IpAddr'' and wait
%% for any replies.  Returns
%% ``not_found'' if there is no switch connected from ``IpAddrr'',
%% ``{ok, Reply}''
%% if the message is sent successfully, or ``error'' if there was an error
%% sending the request to the switch.  ``Reply'' is ``no_reply'' if there
%% was no reply to the request, or ``Reply'' is an ``ofp_message'' record
%% that may be decoded with ``of_msg_lib:decode/1''.
%% @end
-spec sync_send(switch_key() | default, ofp_message()) -> {ok, no_reply | ofp_message()} | {error, error_reason()}.
sync_send(SwitchKey, Msg) ->
    ?call(SwitchKey, {sync_send, Msg}).

-spec send(switch_key() | default, ofp_message()) -> {ok, no_reply | ofp_message()} | {error, error_reason()}.
send(SwitchKey, Msg) ->
    ?cast(SwitchKey, {send, Msg}).

-spec connect(ipaddress(), inet:port_number()) -> ok | {error, error_reason()}.
connect(IpAddr, Port) ->
    case of_driver:connect(IpAddr, Port) of
        {ok, _} -> ok;
        Error -> Error
    end.

find_proc(AppName, SwitchKey) ->
    case get_switch(SwitchKey) of
        #loom_switch_info_t{clients = #{AppName := Proc}} -> Proc;
        _ -> not_found
    end.

find_loom(SwitchKey) when is_integer(SwitchKey) ->
    loom_utils:proc_name(?MODULE, SwitchKey);
find_loom(DataPathId) ->
    case ets:match_object(?EtsLoom, #loom_switch_info_t{datapath_id = DataPathId, _='_'}) of
        [#loom_switch_info_t{key = SwitchKey}] -> find_loom(SwitchKey);
        _ -> not_found
    end.

-spec close_connection(switch_key() | default) -> ok | {error, error_reason()}.
close_connection(SwitchKey) ->
    ?call(find_loom(SwitchKey), close_connection).

subscribe(SwitchKey, MsgType) ->
    ?call(SwitchKey, {subscribe, SwitchKey, MsgType}).

filter(Op, SwitchKey, Filter, Pid) ->
    ?cast(SwitchKey, {filter, Op, SwitchKey, Filter, Pid}).

get_switch(SwitchKey) when is_integer(SwitchKey) ->
    case ets:lookup(?EtsLoom, SwitchKey) of
        [] -> not_found;
        [#loom_switch_info_t{} = SwitchInfo] -> SwitchInfo
    end;
get_switch(DataPathId) when is_list(DataPathId) ->
    case ets:match_object(?EtsLoom, #loom_switch_info_t{datapath_id = DataPathId, _='_'}) of
        [#loom_switch_info_t{} = SwitchInfo] -> SwitchInfo;
        _ -> not_found
    end;
get_switch(#state{key = SwitchKey}) ->
    get_switch(SwitchKey).

get_ports_info(SwitchKey) ->
    ?call(SwitchKey, get_ports_info).

%%%===================================================================
%%% API
%%%===================================================================

start(#loom_switch_info_t{key = SwitchKey} = SwitchInfo) ->
    ProcName = loom_utils:proc_name(?MODULE, SwitchKey),
    loom_handler_sup:start_child(
        ProcName,
        loom_handler_sup:childspec(ProcName, ?MODULE, [ProcName, SwitchInfo])
    ).

stop(Pid) ->
    loom_handler_sup:stop_child(Pid).

start_link(ProcName, SwitchInfo) ->
    gen_server:start_link({local, ProcName}, ?MODULE, [SwitchInfo], []).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?EtsLoom, [named_table, {keypos, 2}, set, public]),
    {ok, #loom_logic_state{}};
init([#loom_switch_info_t{key = SwitchKey, datapath_id = DataPathId} = SwitchInfo]) ->
    ProcName = element(2, erlang:process_info(self(), registered_name)),
    ?INFO("~p: Initializing ~p for datapath ~s", [ProcName, ?MODULE, DataPathId]),
    self() ! {register, SwitchInfo},
    process_flag(trap_exit, true),
    {ok, #state{
        key = SwitchKey, datapath_id = DataPathId, proc_name = ProcName
    }}.

handle_call(Request, From, State) ->
    try process_call(Request, State) of
        {reply, ok, _} = Return ->
            ?DEBUG("call: Request From ~p, Returns ~p~n~p", [From, ok, Request]),
            Return;
        {reply, NotOk, _} = Return when is_atom(NotOk) ->
            ?DEBUG("call: Request From ~p, Returns ~p~n~p", [From, NotOk, Request]),
            Return;
        Return ->
            Return
    catch
        Error:Reason:StackTrace ->
            ?ERROR("Failed:~n    Request ~p~n    From ~p~n    Error ~p, Reason ~p~n    StackTrace ~n~s",
                [Request, From, Error, Reason, loom_utils:pretty_print(StackTrace)]),
            {reply, Error, State}
    end.

handle_cast(Request, State) ->
    ?DEBUG("cast: Request ~p", [Request]),
    try process_cast(Request, State) of
        Return ->
            Return
    catch
        Error:Reason:StackTrace ->
            ?ERROR("Failed:~n    Request ~p~n    Error ~p, Reason ~p~n    StackTrace ~n~s",
                [Request, Error, Reason, loom_utils:pretty_print(StackTrace)]),
            {noreply, State}
    end.

handle_info(Info, State) ->
    ?DEBUG("info: Request ~p", [Info]),
    try process_info_msg(Info, State) of
        Return ->
            Return
    catch
        Error:Reason:StackTrace ->
            ?ERROR("Failed:~n    Request ~p~n    Error ~p, Reason ~p~n    StackTrace ~n~s",
                [Info, Error, Reason, loom_utils:pretty_print(StackTrace)]),
            {noreply, State}
    end.

terminate(_Reason, #state{proc_name = ProcName}) ->
    ?INFO("~p going down: ~p", [ProcName, _Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%%===================================================================
%%% Internal functions
%%%===================================================================
process_call({sync_send, Msg}, State) ->
    {reply, do_send(sync, get_switch(State), Msg), State};
process_call(close_connection, State) ->
    {reply, do_close_connection(get_switch(State)), State};
process_call({subscribe, SwitchKey, MsgType}, State) ->
    {reply, do_subscribe(SwitchKey, MsgType), State};
process_call({filter, Op, DatapathId, Filter, Pid}, State) ->
    {reply, do_filter(Op, DatapathId, Filter, Pid), State};
process_call(get_ports_info, State) ->
    {reply, do_get_ports_info(get_switch(State)), State};

process_call({init, SwitchInfo}, #loom_logic_state{next_switch_key = SwitchKey} = State) ->
    {ok, _} = start(SwitchInfo#loom_switch_info_t{key = SwitchKey}),
    {reply, ok, State#loom_logic_state{next_switch_key = SwitchKey+1}};
process_call({stop, DatapathId}, State) ->
    do_unregister(get_switch(DatapathId)),
    {reply, ok, State};

process_call(Request, State) ->
    ?INFO("call: Unhandled Request ~p", [Request]),
    {reply, ok, State}.

process_cast({send, Msg}, State) ->
    do_send(async, get_switch(State), Msg),
    {noreply, State};
process_cast({filter, Op, DatapathId, Filter, Pid}, State) ->
    do_filter(Op, DatapathId, Filter, Pid),
    {noreply, State};

process_cast(Request, State) ->
    ?INFO("cast: Request~n~p", [Request]),
    {noreply, State}.

process_info_msg({register, Request}, State) ->
    do_register(Request),
    {noreply, State};

process_info_msg(Request, State) ->
    ?INFO("info: Request~n~p", [Request]),
    {noreply, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

do_register(
    #loom_switch_info_t{} = InitSwitchInfo) ->

    SwitchInfo = InitSwitchInfo#loom_switch_info_t{
        ports_map = do_get_ports_info(InitSwitchInfo)
    },

    ets:insert(?EtsLoom, SwitchInfo),

    do_initialize_ports(SwitchInfo),

    do_default_flows(SwitchInfo),

    do_subscribe(SwitchInfo, [packet_in, port_status]),

    true = ets:insert(?EtsLoom, SwitchInfo#loom_switch_info_t{
        clients = do_start_apps(SwitchInfo)
    }).

do_unregister(#loom_switch_info_t{key = SwitchId, clients = Clients}) ->
    do_stop_apps(Clients),
    true = ets:delete(?EtsLoom, SwitchId),
    ok;
do_unregister(_) ->
    not_found.

do_start_apps(
        #loom_switch_info_t{
            key = SwitchId,
            ip_addr = IpAddress,
            datapath_id = DatapathId,
            version = Version,
            ports_map = PortsMap
        }) ->
    Clients = #{
        ?MODULE => self()
    },
    case application:get_env(?AppName, apps) of
        {ok, Apps} ->
            lists:foldl(fun
                (AppName, Acc) ->
                    Ret = AppName:start(#switch_info_t{
                        switch_id = SwitchId,
                        datapath_id = DatapathId,
                        version = Version,
                        ip_addr = IpAddress,
                        ports_map = PortsMap
                    }),
                    case Ret of
                        {ok, Pid} ->
                            Acc#{AppName => Pid};
                        _ ->
                            Acc
                    end
            end, Clients, Apps);
        _ ->
            Clients
    end.

do_stop_apps(AppInfo) when is_map(AppInfo) ->
    lists:foreach(fun
        ({Mod, Arg}) ->
            Mod:stop(Arg)
    end, maps:to_list(AppInfo)).

do_close_connection(#loom_switch_info_t{datapath_id = DatapathId}) ->
    ofs_handler:terminate(DatapathId);
do_close_connection(_) ->
    not_found.

do_send(_, Error = not_found, _Msg) ->
    Error;
do_send(_, #loom_switch_info_t{connection = down}, _Msg) ->
    ok;
do_send(Type, SwitchKey, Msg) when is_integer(SwitchKey) ->
    do_send(Type, get_switch(SwitchKey), Msg);
do_send(Type, #loom_switch_info_t{version = Version} = SwitchInfo, [Function | Args])
    when not is_record(Function, ofp_message) ->
    OfpMsg = erlang:apply(of_msg_lib, Function, [Version] ++ Args),
    do_send(Type, SwitchInfo, OfpMsg);
do_send(Type, #loom_switch_info_t{version = Version} = SwitchInfo, Function) when is_atom(Function) ->
    OfpMsg = erlang:apply(of_msg_lib, Function, [Version]),
    do_send(Type, SwitchInfo, OfpMsg);
do_send(sync, #loom_switch_info_t{datapath_id = DatapathId}, Msg) ->
    Ret = case is_list(Msg) of
        true ->
            ofs_handler:sync_send_list(DatapathId, Msg);
        _ ->
            ofs_handler:sync_send(DatapathId, Msg)
    end,
    case Ret of
        {ok, OfpMsg} when is_record(OfpMsg, ofp_message) ->
            of_msg_lib:decode(OfpMsg);
        {ok, _} ->
            ok;
        R ->
            R
    end;
do_send(async, #loom_switch_info_t{datapath_id = DatapathId}, Msg) ->
    case is_list(Msg) of
        true ->
            ofs_handler:send_list(DatapathId, Msg);
        _ ->
            ofs_handler:send(DatapathId, Msg)
    end.

do_subscribe(_, []) ->
    ok;
do_subscribe(SwitchInfo, [H|R]) ->
    do_subscribe(SwitchInfo, H), do_subscribe(SwitchInfo, R);
do_subscribe(#loom_switch_info_t{datapath_id = DatapathId}, MsgType) ->
    ofs_handler:subscribe(DatapathId, loom_ofsh, MsgType);
do_subscribe(Error, _Msg) ->
    Error.

do_filter(_, not_found, _, _) ->
    not_found;
do_filter(delete, DatapathId, NotifyKey, _) ->
    Table = ets_loom,
    case ets:lookup(Table, NotifyKey) of
        [#loom_notification_t{dp_list = DpMap} = PktFilter] ->
            case maps:get(DatapathId, DpMap, []) of
                [] ->
                    ok;
                _ when map_size(DpMap) == 1 ->
                    ets:delete(Table, NotifyKey);
                _ ->
                    ets:insert(Table,
                        PktFilter#loom_notification_t{
                            key = NotifyKey,
                            dp_list = maps:remove(DatapathId, DpMap)
                        }
                    )
            end;
        [] ->
            ok
    end,
    ok;
do_filter(add, DatapathId, PktDesc, Pid) ->
    Table = ets_loom,
    case ets:lookup(Table, PktDesc) of
        [#loom_notification_t{dp_list = PidMap} = PktFilter] ->
            ets:insert(Table,
                PktFilter#loom_notification_t{
                    key = PktDesc,
                    dp_list = PidMap#{DatapathId => Pid}
                });
        _ ->
            ets:insert(Table,
                #loom_notification_t{
                    key = PktDesc,
                    dp_list = #{DatapathId => Pid}
                })
    end,
    ok.

do_default_flows(#loom_switch_info_t{version = Version} = SwitchInfo) ->
    %% Delete all flows before provisioning the switch
    do_send(sync, SwitchInfo,
        of_msg_lib:flow_delete(Version, [], [{table_id, 16#ff}])),

    Request = of_msg_lib:flow_add(
        Version,
        [],                         %% Matches: any port
        [{apply_actions, [          %% Actions: Send such a packet to controller
            {output, 'controller', no_buffer}
        ]}],
        [{priority,0}]       %% Priority of 16#0
    ),
    do_send(sync, SwitchInfo, Request).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

do_get_ports_info(
        #loom_switch_info_t{
            version = Version
        } = SwitchInfo) ->
    {port_desc_reply, _, [{flags, _}, {ports, PortList}]} =
        do_send(sync, SwitchInfo,
            of_msg_lib:get_port_descriptions(Version)),

    lists:foldl(fun
        (PropList, Acc) ->
            PortId = proplists:get_value(port_no, PropList),
            Acc#{
                PortId => #port_info_t{
                    name = proplists:get_value(name, PropList),
                    port_no = PortId,
                    hw_addr = proplists:get_value(hw_addr, PropList, <<>>),
                    if_speed = proplists:get_value(curr_speed, PropList, 10000),
                    state = lists:member(live, proplists:get_value(state, PropList, []))
                }
            }
    end, #{}, PortList);
do_get_ports_info(_) ->
    #{}.

do_initialize_ports(SwitchInfo) ->
    case application:get_env(?AppName, interfaces) of
        {ok, CfgProperties} ->
            case proplists:get_value(enable, CfgProperties, false) of
                true ->
                    do_enable_ports(SwitchInfo);
                _ ->
                    ok
            end;
        _ ->
            ok
    end.

do_enable_ports(
    #loom_switch_info_t{
        ports_map = PortsMap,
        version = Version
    } = SwitchInfo) ->

    PortModCfg = PortModCfg = maps:fold(fun
        (PortId,#port_info_t{hw_addr = HwAddr}, Acc) ->
            [of_msg_lib:set_port_up(Version,HwAddr,PortId) | Acc]
    end,[],PortsMap),
    do_send(async, SwitchInfo, PortModCfg),
    ok.