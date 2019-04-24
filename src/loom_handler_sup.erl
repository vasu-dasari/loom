%%%-------------------------------------------------------------------
%%% @author vdasari
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 22. Apr 2019 13:56
%%%-------------------------------------------------------------------
-module(loom_handler_sup).
-author("vdasari").

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-export([start_child/2,stop_child/1,show_children/0,childspec/3]).

-define(SERVER, ?MODULE).

-define(Process(Name, Type),
    {Name, {Name, start_link, []}, temporary, 2000, Type, [Name]}).

-include_lib("loom/include/logger.hrl").
%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
    {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
    {ok, {SupFlags :: {RestartStrategy :: supervisor:strategy(),
        MaxR :: non_neg_integer(), MaxT :: non_neg_integer()},
        [ChildSpec :: supervisor:child_spec()]
    }} |
    ignore |
    {error, Reason :: term()}).
init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    {ok, {SupFlags, [
    ]}}.

childspec(ProcName, AppName, Arg) ->
    #{
        id => ProcName,
        start => {AppName, start_link, Arg}
    }.

start_child(ProcName, ChildSpec) when is_map(ChildSpec) ->
    case whereis(ProcName) of
        undefined ->
            do_add_child(ChildSpec);
        Pid ->
            do_delete_child(Pid),
            do_add_child(ChildSpec)
    end.

stop_child(Pid) when is_pid(Pid) ->
    {_,Name} = erlang:process_info(Pid, registered_name),
    stop_child(Name);
stop_child(Name) ->
    do_delete_child(Name).

show_children() ->
    lists:foreach(fun
        ({Name, Pid, worker, _}) ->
            io:format("~16s  => ~p~n", [Name, Pid])
    end, supervisor:which_children(?MODULE)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

do_add_child(ChildSpec) ->
    supervisor:start_child(?SERVER, ChildSpec).

do_delete_child(Pid) ->
    gen_server:stop(Pid),
    ok = supervisor:terminate_child(?SERVER, Pid).
