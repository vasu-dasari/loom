%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 04. Feb 2018 11:10 AM
%%%-------------------------------------------------------------------
-module(loom_interface).
-author("vdasari").

-include("loom_api.hrl").

-callback start(SwitchInfo :: #switch_info_t{}) ->
    {'ok', Pid::pid()} | {'ok'} | {'ok', State::term()} | {'error', Reason::term()}.

-callback stop(SwitchInfo :: #switch_info_t{}) ->
    {'ok', State::term()} | {'error', Reason::term()}.

%%-callback info(SwitchInfo :: #switch_info_t{}) ->
%%    {'ok', State::term()} | {'error', Reason::term()}.
