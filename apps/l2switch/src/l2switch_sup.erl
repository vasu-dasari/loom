%%%-------------------------------------------------------------------
%% @doc l2switch top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(l2switch_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-export([start_child/2, stop_child/1, show_children/0]).

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
    RestartStrategy = simple_one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,
    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},
    {ok, {SupFlags, [
        ?Process(l2switch, worker)
    ]}}.

start_child(ProcName, Arg) ->
    case whereis(ProcName) of
        undefined ->
            do_add_child(ProcName, Arg);
        Pid ->
            do_delete_child(Pid),
            do_add_child(ProcName, Arg)
    end.

stop_child(Pid) when is_pid(Pid) ->
    do_delete_child(Pid).

show_children() ->
    lists:foreach(fun
        ({undefined, Pid, worker, _}) ->
            {_,Name} = erlang:process_info(Pid, registered_name),
            io:format("~16s  => ~p~n", [Name, Pid])
    end, supervisor:which_children(?MODULE)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

do_add_child(ProcName, Arg) ->
    supervisor:start_child(?SERVER, [ProcName, Arg]).

do_delete_child(Pid) ->
    gen_server:stop(Pid),
    ok = supervisor:terminate_child(?SERVER, Pid).
