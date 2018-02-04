%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 18. Jan 2018 9:56 AM
%%%-------------------------------------------------------------------

-module(loom_ofsh).

-include_lib("ofs_handler/include/ofs_handler.hrl").
-include_lib("of_protocol/include/of_protocol.hrl").

-include("logger.hrl").

-export([
    init/7,
    connect/8,
    disconnect/1,
    failover/1,
    handle_message/2,
    handle_error/2,
    terminate/1
]).

-behaviour(ofs_handler).

% State held by ofs_handler.
% This state holds onto the datapath id and aux connection id.
% There is one state for each connection.  
-record(loom_ofs_state, {
    datapath_id,
    aux_id = 0
}).
-type ofs_state() :: #loom_ofs_state{}.

% callbacks from ofs_handler
% The callback functions in turn call loom_logic for processing.
-spec init(handler_mode(), ipaddress(), datapath_id(), features(), of_version(), connection(), options()) -> {ok, ofs_state()}.
init(Mode, IpAddr, DatapathId, _Features, Version, Connection, _Opts) ->
    ok = loom_logic:ofsh_init(Mode, IpAddr, DatapathId, Version, Connection),
    State = #loom_ofs_state{datapath_id = DatapathId},
    {ok, State}.

-spec connect(handler_mode(), ipaddress(), datapath_id(), features(), of_version(), connection(), auxid(), options()) -> {ok, ofs_state()}.
connect(Mode, IpAddr, DatapathId, _Features, Version, Connection, AuxId, _Opts) ->
    ok = loom_logic:ofsh_connect(Mode, IpAddr, DatapathId, Version, Connection, AuxId),
    State = #loom_ofs_state{datapath_id = DatapathId, aux_id = AuxId},
    {ok, State}.

-spec disconnect(ofs_state()) -> ok.
disconnect(State) ->
    #loom_ofs_state{
        datapath_id = DatapathId,
        aux_id = AuxId
    } = State,
    ok = loom_logic:ofsh_disconnect(AuxId, DatapathId).

-spec failover(ofs_state()) -> {ok, ofs_state()}.
failover(State) ->
    ok = loom_logic:ofsh_failover(),
    {ok, State}.

-spec handle_error(error_reason(), ofs_state()) -> ok.
handle_error(Reason, State) ->
    DatapathId = State#loom_ofs_state.datapath_id,
    ok = loom_logic:ofsh_handle_error(DatapathId, Reason).

-spec handle_message(ofp_message(), ofs_state()) -> ok.
handle_message(Msg, State) ->
    DatapathId = State#loom_ofs_state.datapath_id,
    ok = loom_logic:ofsh_handle_message(DatapathId, Msg).

-spec terminate(ofs_state()) -> ok.
terminate(State) ->
    DatapathId = State#loom_ofs_state.datapath_id,
    ok = loom_logic:ofsh_terminate(DatapathId).
