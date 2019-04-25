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
-define(ip_address(State), (State#state.switch_info)#switch_info_t.ip_addr).

-record(state, {
    switch_info,
    if_list = #{},
    l2_table = #{},
    rx_packets = 0,
    tx_packets = 0
}).

%%%===================================================================
%%% API
%%%===================================================================
start(SwitchInfo) ->
    ProcName = loom_utils:proc_name(?MODULE,SwitchInfo),
    loom_handler_sup:start_child(
        ProcName,
        loom_handler_sup:childspec(ProcName, ?MODULE, [ProcName, SwitchInfo])
    ).

stop(Pid) ->
    loom_handler_sup:stop_child(Pid).

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

process_info_msg({init}, #state{switch_info = #switch_info_t{datapath_id = DatapathId, ports_map = PortsMap}} = State) ->
    ?INFO("~p: Initializing ~p", [element(2, erlang:process_info(self(), registered_name)), ?MODULE]),
    loom_logic:filter(add, DatapathId,
        #loom_pkt_desc_t{
        }, self()),

    {noreply, State#state{
        if_list = PortsMap
    }};

process_info_msg({rx_packet, PortId, Packet}, State) ->
    {noreply, do_process_rx_packet(PortId, Packet, State)};

process_info_msg(Request, State) ->
    ?INFO("info: Request~n~p", [Request]),
    {noreply, State}.

do_process_rx_packet(PortId, Packet, #state{l2_table = L2Table} = State) ->
    PktDecode = pkt:decapsulate(Packet),

    ?DEBUG("~p(~s): Packet ~n~s", [
        PortId, port2str(PortId, State),
        loom_utils:record_to_proplist(to_str,PktDecode)
    ]),

    {SrcMac, DstMac, VlanId} = case PktDecode of
        [#ether{shost = S, dhost = D, type = 16#8100}, #'802.1q'{vid = V} | _] ->
            {S, D, V};
        [#ether{shost = S, dhost = D} | _] ->
            {S, D, 0}
    end,

    case do_learn_mac(PortId, SrcMac, VlanId, State) of
        ok ->
            case do_skip_packet(PktDecode) of
                true ->
                    ok;
                _ ->
                    do_forward_packet(DstMac, VlanId, Packet, State)
            end,
            State#state{
                l2_table = L2Table#{{SrcMac, VlanId} => PortId},
                rx_packets = ?incr_rx_packets(State)
            };
        _ ->
            State
    end.

do_forward_packet(DstMac, VlanId, Packet, #state{l2_table = L2Table} = State) ->
    case maps:get({DstMac, VlanId}, L2Table, []) of
        [] ->
            loom_logic:send(?switch_id(State),
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
            loom_logic:send(?switch_id(State),
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

do_skip_packet(PktDecode) ->
    lists:foldl(fun
        (#lldp{}, false) ->
            true;
        (_, Acc) ->
            Acc
    end, false, PktDecode).

port2str(PortId, #state{if_list = IfList}) ->
    case maps:get(PortId, IfList, []) of
        #port_info_t{name = N} ->
            binary_to_list(N);
        _ ->
            "none"
    end.