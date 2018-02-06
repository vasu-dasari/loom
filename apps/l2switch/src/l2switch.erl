%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 05. Feb 2018 10:11 AM
%%%-------------------------------------------------------------------
-module(l2switch).
-author("vdasari").

-behaviour(gen_server).
-behavior(loom_interface).

-include_lib("loom/include/logger.hrl").
-include_lib("loom/include/loom_api.hrl").
-include_lib("pkt/include/pkt.hrl").

%% API
-export([start_link/2]).

%% gen_server callbacks

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-export([start/1, stop/1]).

-define(incr_rx_packets(State), (State#state.rx_packets + 1)).
-define(incr_tx_packets(State), (State#state.tx_packets + 1)).
-define(SERVER, ?MODULE).

-define(version(State),     (State#state.switch_info)#switch_info_t.version).
-define(switch_id(State),   (State#state.switch_info)#switch_info_t.switch_id).
-define(datapath_id(State), (State#state.switch_info)#switch_info_t.datapath_id).

-record(state, {
    switch_info,
    if_list = #{},
    l2_table = #{},
    rx_packets = 0,
    tx_packets = 0
}).

-record(port_info_t, {
    name,
    port_no,
    state
}).

%%%===================================================================
%%% API
%%%===================================================================
start(SwitchInfo) ->
    l2switch_sup:start_child(loom_utils:proc_name(?MODULE, SwitchInfo), SwitchInfo).

stop(Pid) when is_pid(Pid) ->
    ?INFO("Stopping ~p: Switch ~p", [?MODULE, Pid]),
    l2switch_sup:stop_child(Pid);
stop(SwitchInfo) ->
    ?INFO("Stopping ~p: Switch ~p", [?MODULE, SwitchInfo]),
    ok.

start_link(ProcName, SwitchInfo) ->
    gen_server:start_link({local, ProcName}, ?MODULE, [SwitchInfo], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([SwitchInfo]) ->
    self() ! {init},
    {ok, #state{
        switch_info = SwitchInfo
    }}.

handle_call(Request, From, State) ->
    try process_call(Request, State) of
        {reply, ok, _} = Return ->
            ?DEBUG("call: Request From ~p, Returns ~p~n~p", [From, ok, Request]),
            Return;
        {reply, NotOk, _} = Return when is_atom(NotOk) ->
            ?INFO("call: Request From ~p, Returns ~p~n~p", [From, NotOk, Request]),
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
process_call(Request, State) ->
    ?INFO("call: Unhandled Request ~p", [Request]),
    {reply, ok, State}.

process_cast(Request, State) ->
    ?INFO("cast: Request~n~p", [Request]),
    {noreply, State}.

process_info_msg({init}, #state{switch_info = #switch_info_t{switch_id = SwitchId, datapath_id = DatapathId}} = State) ->
    ?INFO("Initializing switch~n~p", [State]),
    loom_logic:filter(add, DatapathId,
        #loom_pkt_desc_t{
        }, self()),

    {port_desc_reply, _, [{flags,_}, {ports,PortList}]} =
        loom_logic:sync_send(SwitchId, get_port_descriptions),
    IfList = lists:foldl(fun
        (PropList, Acc) ->
            PortId = proplists:get_value(port_no, PropList),
            Acc#{
                PortId => #port_info_t{
                    name = proplists:get_value(name, PropList),
                    port_no = PortId,
                    state = lists:member(live, proplists:get_value(state, PropList, []))
                }
            }
    end, #{}, PortList),
    {noreply, State#state{
        if_list = IfList
    }};

process_info_msg({rx_packet, PortId, Packet}, State) ->
    {noreply, do_process_rx_packet(PortId, Packet, State)};

process_info_msg(Request, State) ->
    ?INFO("info: Request~n~p", [Request]),
    {noreply, State}.

-record(l2_entry_t, {
    key :: {binary(), non_neg_integer()},
    port_id
}).

do_process_rx_packet(PortId, Packet, #state{l2_table = L2Table} = State) ->
    PktDecode = pkt:decapsulate(Packet),

    ?DEBUG("Packet ~n~p", [PktDecode]),
    {SrcMac, DstMac, VlanId} = case PktDecode of
        [#ether{shost = S, dhost = D, type = 16#8100}, #ieee802_1q_tag{vid = V} | _] ->
            {S, D, V};
        [#ether{shost = S, dhost = D} | _] ->
            {S, D, 0}
    end,

    case do_learn_mac(PortId, SrcMac, VlanId, State) of
        ok ->
            do_forward_packet(DstMac, VlanId, Packet, State);
        _ ->
            ok
    end,

    State#state{
        l2_table = L2Table#{{SrcMac, VlanId} => PortId},
        rx_packets = ?incr_rx_packets(State)
    }.

do_forward_packet(DstMac, VlanId, Packet, #state{l2_table = L2Table} = State) ->
    case maps:get({DstMac, VlanId}, L2Table, []) of
        [] ->
            loom_logic:sync_send(?switch_id(State),
                of_msg_lib:send_packet(?version(State),
                    Packet,
                    'controller',
                    [{output, 'flood', no_buffer}]
                ));
        _ ->
            ok
    end.

do_learn_mac(PortId, SrcMac, VlanId, #state{l2_table = L2Table} = State) ->
    case maps:get({SrcMac, VlanId}, L2Table, []) of
        [] ->
            Match = case VlanId == 0 of
                true -> [{eth_dst, SrcMac}];
                _ -> [{eth_dst, SrcMac}, {vlan_vid, VlanId}]
            end,
            loom_logic:sync_send(?switch_id(State),
                of_msg_lib:flow_add(?version(State),
                    Match,
                    [{apply_actions, [
                        {output, PortId, no_buffer}
                    ]}],
                    [{priority, 100}]
                )),
            ok;
        P when P /= PortId ->
            mac_move;
        _ ->
            ok
    end.