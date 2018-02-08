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
-export([start_link/0]).

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
    switches/0,
    sync_send/2,
    connect/2,
    close_connection/1,
    set_default/1,
    show_default/0,
    ofs_version/1, subscribe/2]).

-export([get_switch/1, get_ports_info/1]).

-export([filter/4]).

-define(AppName, loom).
-define(EtsLoom, ets_loom).
-define(SERVER, ?MODULE).

-type switch_key() :: undefined | integer().

-record(loom_logic_state, {
    next_switch_key = 1 :: integer(),
    switches_table :: term(), % ets table
    default_switch :: switch_key()
}).

-record(loom_switch_info_t, {
    key             :: {id, integer()},
    ip_addr,
    datapath_id,
    version,
    filters = #{},
    clients = #{},
    ports_map = #{},
    connection
}).

%% ----------------------------------------------------------------------------
%% Callback API
%% ----------------------------------------------------------------------------

% These functions are called from loom_ofsh.erl.
-spec ofsh_init(handler_mode(), ipaddress(), datapath_id(), features(), of_version(), connection()) -> ok.
ofsh_init(active, IpAddr, DatapathId, Features, Version, Connection) ->
    % new main connection
    ?INFO("Switch discvered at ~s, Datapath Id ~s~n", [
        inet_utils:convert_ip(to_string,IpAddr), DatapathId
    ]),
    ok = gen_server:call(?MODULE, {init, IpAddr, DatapathId, Features, Version, Connection}),
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
    ?INFO("Switch ~s is disconnected", [DatapathId]),
    ok = gen_server:call(?MODULE, {terminate, DatapathId}).

%% ----------------------------------------------------------------------------
%% Utility API
%% ----------------------------------------------------------------------------

%% @doc
%% Returns the list of connected switches.  The returned tuples have
%% the IP address of the switch (for calling loom_logic
%% functions), the datapath id (for calling ofs_handler),
%% the open flow version number (for calling of_msg_lib), the
%% connection (for calling of_driver).
%% @end
-spec switches() -> [{switch_key(), datapath_id(), ipaddress(), of_version(), connection()}].
switches() ->
    gen_server:call(?SERVER, switches).

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
    gen_server:call(?SERVER, {sync_send, SwitchKey, Msg}).

-spec connect(ipaddress(), inet:port_number()) -> ok | {error, error_reason()}.
connect(IpAddr, Port) ->
    case of_driver:connect(IpAddr, Port) of
        {ok, _} -> ok;
        Error -> Error
    end.

-spec close_connection(switch_key() | default) -> ok | {error, error_reason()}.
close_connection(SwitchKey) ->
    gen_server:call(?SERVER, {close_connection, SwitchKey}).

-spec set_default(switch_key()) -> ok | {error, error_reason()}.
set_default(SwitchKey) ->
    gen_server:call(?SERVER, {set_default, SwitchKey}).

-spec show_default() -> switch_key() | undefined.
show_default() ->
    gen_server:call(?SERVER, show_default).

-spec ofs_version(switch_key() | default) -> of_version() | {error, error_reason()}.
ofs_version(SwitchKey) ->
    gen_server:call(?SERVER, {ofs_version, SwitchKey}).

subscribe(SwitchKey, MsgType) ->
    gen_server:call(?SERVER, {subscribe, SwitchKey, MsgType}).

filter(Op, SwitchId, Filter, Pid) ->
    gen_server:call(?SERVER, {filter, Op, SwitchId, Filter, Pid}).

get_switch(Key) ->
    gen_server:call(?SERVER, {switch, get, Key}).

get_ports_info(Key) ->
    gen_server:call(?SERVER, {get_ports_info, Key}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    self() ! {init},
    {ok, #loom_logic_state{}}.

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
        Error:Reason ->
            StackTrace = erlang:get_stacktrace(),
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
        Error:Reason ->
            StackTrace = erlang:get_stacktrace(),
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
        Error:Reason ->
            StackTrace = erlang:get_stacktrace(),
            ?ERROR("Failed:~n    Request ~p~n    Error ~p, Reason ~p~n    StackTrace ~n~s",
                [Info, Error, Reason, loom_utils:pretty_print(StackTrace)]),
            {noreply, State}
    end.

terminate(_Reason, _State) ->
    ?INFO("~s going down: ~p", [?MODULE, _Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%%===================================================================
%%% Internal functions
%%%===================================================================
process_call(Request, State) when element(1, Request) == init ->
    self() ! {register, Request},
    {reply, ok, State};
process_call({terminate, DatapathId}, #loom_logic_state{switches_table = Table} = State) ->
    case find_switch(DatapathId, State) of
        #loom_switch_info_t{} = SwitchInfo ->
            NewSwitchInfo = SwitchInfo#loom_switch_info_t{connection = down},
            ets:insert(Table, NewSwitchInfo),
            self() ! {unregister, NewSwitchInfo};
        _ ->
            ok
    end,
    {reply, ok, State};

process_call({sync_send, SwitchKey, Msg}, State) when is_record(Msg, ofp_message) ->
    {reply, do_sync_send(find_switch(SwitchKey, State), Msg, State), State};
process_call({sync_send, SwitchKey, Msg}, State) ->
    {reply, do_sync_send_api(sync, find_switch(SwitchKey, State), Msg, State), State};

process_call({close_connection, SwitchKey}, State) ->
    {reply, do_close_connection(SwitchKey, State), State};
process_call({set_default, SwitchKey}, State) ->
    {Reply, NewState} = do_set_default(SwitchKey, State),
    {reply, Reply, NewState};
process_call(show_default, State = #loom_logic_state{default_switch = DefaultKey}) ->
    {reply, DefaultKey, State};
process_call({ofs_version, SwitchKey}, State) ->
    {reply, do_get_version(SwitchKey, State), State};
process_call(switches, State) ->
    Reply = [{SwitchKey, DatapathId, IpAddr, Version, Connection} ||
        #loom_switch_info_t{
            key = SwitchKey,
            datapath_id = DatapathId,
            ip_addr = IpAddr,
            version = Version,
            connection = Connection
        } <- do_get_switches(State)],
    {reply, Reply, State};
process_call({subscribe, SwitchKey, MsgType}, State) ->
    {reply, do_subscribe(SwitchKey, MsgType, State), State};
process_call({filter, Op, DatapathId, Filter, Pid}, State) ->
    {reply, do_filter(Op, DatapathId, Filter, Pid, State), State};
process_call({get_ports_info, Key}, State) ->
    {reply, do_get_ports_info(find_switch(Key, State), State), State};
process_call({switch, get, Key}, State) ->
    SwitchInfo = case find_switch(Key, State) of
        #loom_switch_info_t{} = LoomSwitchInfo ->
            #switch_info_t{
                switch_id = LoomSwitchInfo#loom_switch_info_t.key,
                datapath_id =  LoomSwitchInfo#loom_switch_info_t.datapath_id,
                ip_addr =  LoomSwitchInfo#loom_switch_info_t.ip_addr,
                version =  LoomSwitchInfo#loom_switch_info_t.version
            };
        _ ->
            not_found
    end,
    {reply, SwitchInfo, State};

process_call(Request, State) ->
    ?INFO("call: Unhandled Request ~p", [Request]),
    {reply, ok, State}.

process_cast(Request, State) ->
    ?INFO("cast: Request~n~p", [Request]),
    {noreply, State}.

process_info_msg({init}, State) ->
    {noreply, State#loom_logic_state{
        switches_table = ets:new(?EtsLoom, [named_table, {keypos, 2}, set, public]),
        default_switch = undefined
    }};

process_info_msg({initialize,
    #loom_switch_info_t{
        key = SwitchId
    } = SwitchInfo}, State) ->

    do_default_flows(SwitchInfo, State),

    do_subscribe(SwitchId, [packet_in, port_status], State),
    {noreply, State};

process_info_msg({register, Request}, State) ->
    {noreply, do_register(Request, State)};

process_info_msg({unregister,SwitchInfo}, State) ->
    {noreply, do_unregister(SwitchInfo, State)};

process_info_msg(Request, State) ->
    ?INFO("info: Request~n~p", [Request]),
    {noreply, State}.

do_default_flows(#loom_switch_info_t{key = SwitchId, version = Version}, State) ->
    Request = of_msg_lib:flow_add(
        Version,
        [],                         %% Matches: any port
        [{apply_actions, [          %% Actions: Send such a packet to controller
            {output, 'controller', no_buffer}
        ]}],
        [{priority,0}]       %% Priority of 16#0
    ),
    do_sync_send(SwitchId, Request, State).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

do_register({init, IpAddress, DatapathId, _Features, Version, Connection},
        State = #loom_logic_state{
            switches_table = Switches,
            next_switch_key = SwitchId
        }) ->
    ?INFO("Features ~p", [Features]),
    ?INFO("Features: decode ~p", [of_msg_lib:decode(Version,Features)]),
    SwitchInfo = #loom_switch_info_t{
        key = SwitchId,
        ip_addr = IpAddress,
        datapath_id = DatapathId,
        version = Version,
        connection = Connection
    },

    true = ets:insert(Switches,
        SwitchInfo#loom_switch_info_t{
            clients = do_start_apps(SwitchInfo),
            ports_map = do_get_ports_info(SwitchInfo, State)
        }),

    do_default_flows(SwitchInfo, State),

    do_subscribe(SwitchId, [packet_in, port_status], State),

    State#loom_logic_state{
        next_switch_key = SwitchId + 1
    }.

do_unregister(
    #loom_switch_info_t{
        key = SwitchId,
        clients = Clients
    } = _SwitchInfo, #loom_logic_state{switches_table = Table} = State) ->

    do_stop_apps(Clients),

    true = ets:delete(Table, SwitchId),
    State.

do_start_apps(
        #loom_switch_info_t{
            key = SwitchId,
            ip_addr = IpAddress,
            datapath_id = DatapathId,
            version = Version
        }) ->
    case application:get_env(?AppName, apps) of
        {ok, Apps} ->
            lists:foldl(fun
                (AppName, Acc) ->
                    Ret = AppName:start(#switch_info_t{
                        switch_id = SwitchId,
                        datapath_id = DatapathId,
                        version = Version,
                        ip_addr = IpAddress
                    }),
                    case Ret of
                        {ok, Pid} ->
                            Acc#{AppName => Pid};
                        _ ->
                            Acc
                    end
            end, #{}, Apps);
        _ ->
            #{}
    end.

do_stop_apps(AppInfo) when is_map(AppInfo) ->
    lists:foreach(fun
        ({Mod, Arg}) ->
            ?INFO("~p: Stopping ~p, ~p", [?MODULE, Mod, Arg]),
            Mod:stop(Arg)
    end, maps:to_list(AppInfo)).

find_switch(Key, State) ->
    case do_find_switch(Key, State) of
        [#loom_switch_info_t{} = S] ->
            S;
        _ ->
            not_found
    end.

do_find_switch(default, #loom_logic_state{default_switch = undefined}) ->
    {error, no_default};
do_find_switch(default, State = #loom_logic_state{default_switch = DefaultKey}) ->
    find_switch(DefaultKey, State);
do_find_switch(DatapathId, #loom_logic_state{switches_table = Table}) when is_list(DatapathId) ->
    ets:match_object(Table, #loom_switch_info_t{datapath_id = DatapathId, _ = '_'});
do_find_switch(SwitchKey, #loom_logic_state{switches_table = Switches}) ->
    ets:lookup(Switches, SwitchKey).

do_get_switches(#loom_logic_state{switches_table = Switches}) ->
    ets:tab2list(Switches).

do_get_version(Error = {error, _}, _State) ->
    Error;
do_get_version(#loom_switch_info_t{version = Version}, _State) ->
    Version;
do_get_version(SwitchKey, State) ->
    do_get_version(find_switch(SwitchKey, State), State).

do_set_default(Error = {error, _}, State) ->
    {Error, State};
do_set_default(#loom_switch_info_t{key = DefaultKey}, State) ->
    {ok, State#loom_logic_state{default_switch = DefaultKey}};
do_set_default(SwitchKey, State) ->
    do_set_default(find_switch(SwitchKey, State), State).

do_close_connection(Error = {error, _}, _State) ->
    Error;
do_close_connection(#loom_switch_info_t{datapath_id = DatapathId}, _State) ->
    ofs_handler:terminate(DatapathId);
do_close_connection(SwitchKey, State) ->
    do_close_connection(find_switch(SwitchKey, State), State).

do_sync_send_api(_, SwitchInfo, Msg, State) when is_record(Msg, ofp_message)->
    case do_sync_send(SwitchInfo, Msg, State) of
        {ok, OfpMsg} when is_record(OfpMsg, ofp_message) ->
            of_msg_lib:decode(OfpMsg);
        {ok, _} ->
            ok;
        R ->
            R
    end;
do_sync_send_api(_, #loom_switch_info_t{version = Version} = SwitchInfo, Msg, State) ->
    {Function, Args} = case Msg of
        [F|A] ->
            {F, A};
        F ->
            {F, []}
    end,

    case do_sync_send(SwitchInfo,
        erlang:apply(of_msg_lib, Function, [Version] ++ Args), State) of
        {ok, OfpMsg} when is_record(OfpMsg, ofp_message) ->
            of_msg_lib:decode(OfpMsg);
        {ok, _} ->
            ok;
        R ->
            R
    end.

do_sync_send(Error = not_found, _Msg, _State) ->
    Error;
do_sync_send(#loom_switch_info_t{connection = down}, _Msg, _State) ->
    ok;
do_sync_send(#loom_switch_info_t{datapath_id = DatapathId}, Msg, _State) ->
    ofs_handler:sync_send(DatapathId, Msg);
do_sync_send(SwitchKey, Msg, State) ->
    do_sync_send(find_switch(SwitchKey, State), Msg, State).

do_subscribe(Error = {error, _}, _Msg, _State) ->
    Error;
do_subscribe(_, [], _) ->
    ok;
do_subscribe(SwitchInfo, [H|R], State) when is_record(SwitchInfo, loom_switch_info_t) ->
    do_subscribe(SwitchInfo, H, State), do_subscribe(SwitchInfo, R, State);
do_subscribe(#loom_switch_info_t{datapath_id = DatapathId}, MsgType, _State) ->
    ofs_handler:subscribe(DatapathId, loom_ofsh, MsgType);
do_subscribe(SwitchKey, MsgType, State) ->
    do_subscribe(find_switch(SwitchKey, State), MsgType, State).

do_filter(_, not_found, _, _, _) ->
    not_found;
do_filter(delete, DatapathId, NotifyKey, _, #loom_logic_state{switches_table = Table}) ->
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
do_filter(add, DatapathId, PktDesc, Pid, #loom_logic_state{switches_table = Table}) ->
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

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

do_get_ports_info(
        #loom_switch_info_t{
            version = Version
        } = SwitchInfo, State) ->
    {port_desc_reply, _, [{flags, _}, {ports, PortList}]} =
        do_sync_send_api(sync, SwitchInfo,
            of_msg_lib:get_port_descriptions(Version), State),

    lists:foldl(fun
        (PropList, Acc) ->
            PortId = proplists:get_value(port_no, PropList),
            Acc#{
                PortId => #port_info_t{
                    name = proplists:get_value(name, PropList),
                    port_no = PortId,
                    state = lists:member(live, proplists:get_value(state, PropList, []))
                }
            }
    end, #{}, PortList);
do_get_ports_info(_, _) ->
    #{}.
