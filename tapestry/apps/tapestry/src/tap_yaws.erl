%%------------------------------------------------------------------------------
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%%-----------------------------------------------------------------------------
%%
%% @author Infoblox Inc <info@infoblox.com>
%% @copyright 2013 Infoblox Inc
%% @doc Starts yaws.

-module(tap_yaws).

-behavior(gen_server).

-include("tapestry.hrl").

-export([start_link/1]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(STATE, tap_yaws_state).
-record(?STATE, {
                    supervisor
                }).

%------------------------------------------------------------------------------
% API
%------------------------------------------------------------------------------

start_link(Supervisor) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Supervisor], []).

%------------------------------------------------------------------------------
% gen_server callbacks
%------------------------------------------------------------------------------

init([Supervisor]) ->
    gen_server:cast(?MODULE, start),
    {ok, #?STATE{supervisor = Supervisor}}.

handle_call(Msg, From, State) ->
    error({no_handle_call, ?MODULE}, [Msg, From, State]).

handle_cast(start, State = #?STATE{supervisor = Supervisor}) ->
    ok = start_yaws(Supervisor),
    {noreply, State};
handle_cast(Msg, State) ->
    error({no_handle_cast, ?MODULE}, [Msg, State]).

handle_info(Msg, State) ->
    error({no_handle_info, ?MODULE}, [Msg, State]).

terminate(_Reason, _State) ->
    ok.

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.


%------------------------------------------------------------------------------
% Local Functions
%------------------------------------------------------------------------------

start_yaws(Supervisor) ->
    {web_port, Port} = tap_config:getconfig(web_port),
    {web_address, IpAddr} = tap_config:getconfig(web_address),
    {web_log, LogDir} = tap_config:getenv(web_log),
    {web_doc_root, DocRoot} = tap_config:getenv(web_doc_root),
    {web_id, Id} = tap_config:getenv(web_id),
    GL = [
	  {logdir, LogDir}],
    SL = [
	  {port, Port},
	  {listen, IpAddr}], 
    {ok, SCList, GC, ChildSpecs} =
                        yaws_api:embedded_start_conf(DocRoot, SL, GL, Id),
    [supervisor:start_child(Supervisor, CS) || CS <- ChildSpecs],
    yaws_api:setconf(GC, SCList),
    ok.
