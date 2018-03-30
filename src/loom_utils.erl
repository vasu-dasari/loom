%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2018, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 03. Feb 2018 11:30 PM
%%%-------------------------------------------------------------------
-module(loom_utils).
-author("vdasari").

-include_lib("loom/include/loom_api.hrl").
-include_lib("loom/include/logger.hrl").

%% API
-export([]).

%% API
-export([pretty_print/1, record_to_proplist/1, record_to_proplist/2, proc_name/2, backtrace/0]).

proc_name(Module, #switch_info_t{switch_id = SwitchId}) ->
    list_to_atom(atom_to_list(Module) ++ "_" ++ integer_to_list(SwitchId)).

backtrace() ->
    try throw({ok,whocalledme})
    catch
        _:_ ->
            StackTrace = erlang:get_stacktrace(),
            ?INFO("StackTrace ~n~s",
                [pretty_print(StackTrace)])
    end.

pretty_print(Item) ->
    io_lib:format("~s",[io_lib_pretty:print(Item)]).

record_to_proplist(to_str, R) ->
    pretty_print(record_to_proplist(R)).

-define(R2P(Record),
    record_to_proplist(#Record{} = Rec) ->
        List = [record_to_proplist(R) || R <- tuple_to_list(Rec)],
        ElemList = [{record, Record}] ++ lists:zip(record_info(fields, Record), tl(List)),
        PropList = [{K,V} || {K,V} <- ElemList, (V /= undefined) andalso (V /= []) andalso (V /= <<>>)],
        case PropList of
            [{record, _}] ->
                [];
            _ ->
                PropList
        end
).

record_to_proplist({}) -> [];
?R2P(loom_pkt_desc_t);
?R2P(loom_notification_t);
?R2P(loom_event_t);
?R2P(switch_info_t);
record_to_proplist(List) when is_list(List) ->
    lists:foldr(fun
        (Entry, Acc) ->
            [record_to_proplist(Entry) | Acc]
    end, [], List);
record_to_proplist(Rec) -> Rec.

