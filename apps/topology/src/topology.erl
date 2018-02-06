%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 06. Feb 2018 11:21 AM
%%%-------------------------------------------------------------------
-module(topology).
-author("vdasari").

-behavior(loom_interface).

-include_lib("loom/include/loom_api.hrl").
%% API
-export([start/1, stop/1, neighbor/2]).

%%%===================================================================
%%% loom_interface callbacks
%%%===================================================================

start(SwitchInfo) ->
    Name = loom_utils:proc_name(?MODULE, SwitchInfo),
    lldp_manager:start_handler(Name, loom_lldp, SwitchInfo),
    {ok, Name}.

stop(Name) when is_atom(Name) ->
    lldp_manager:stop_handler(Name).

neighbor(DatapathId, Key) ->
    case loom_logic:get_switch(DatapathId) of
        #switch_info_t{} = SwitchInfo when is_integer(Key) ->
            lldp_manager:get_neighbors(loom_utils:proc_name(?MODULE, SwitchInfo), {if_index, Key});
        #switch_info_t{} = SwitchInfo when is_list(Key) ->
            lldp_manager:get_neighbors(loom_utils:proc_name(?MODULE, SwitchInfo), {chassis, Key});
        #switch_info_t{} = SwitchInfo ->
            lldp_manager:get_neighbors(loom_utils:proc_name(?MODULE, SwitchInfo), Key);
        _ ->
            not_found
    end.