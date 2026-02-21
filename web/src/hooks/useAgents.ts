/**
 * React Query hooks for Aegis API data fetching.
 *
 * All hooks use polling with configurable intervals (default 5s)
 * to keep the dashboard data fresh without WebSocket complexity.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  approveRequest,
  denyRequest,
  getAgentContext,
  getOutput,
  listAgents,
  listPending,
  sendInput,
  startAgent,
  stopAgent,
  restartAgent,
} from "../api/client";
import type {
  AgentContext,
  AgentInfo,
  CommandResponse,
  PendingRequest,
} from "../api/types";

const POLL_INTERVAL_MS = 5_000;

/** Fetch all agents, auto-refreshing every 5 seconds. */
export function useAgents() {
  return useQuery<AgentInfo[], Error>({
    queryKey: ["agents"],
    queryFn: listAgents,
    refetchInterval: POLL_INTERVAL_MS,
    retry: 2,
  });
}

/** Fetch pending requests, auto-refreshing every 5 seconds. */
export function usePending() {
  return useQuery<PendingRequest[], Error>({
    queryKey: ["pending"],
    queryFn: listPending,
    refetchInterval: POLL_INTERVAL_MS,
    retry: 2,
  });
}

/** Fetch agent context for a specific agent. */
export function useAgentContext(name: string) {
  return useQuery<AgentContext, Error>({
    queryKey: ["agentContext", name],
    queryFn: () => getAgentContext(name),
    enabled: !!name,
    refetchInterval: POLL_INTERVAL_MS,
    retry: 2,
  });
}

/** Fetch output lines for a specific agent session. */
export function useAgentOutput(lines?: number) {
  return useQuery<string[], Error>({
    queryKey: ["output", lines],
    queryFn: () => getOutput(lines),
    refetchInterval: POLL_INTERVAL_MS,
    retry: 2,
  });
}

/** Mutation: approve a pending request. */
export function useApproveRequest() {
  const queryClient = useQueryClient();

  return useMutation<CommandResponse, Error, string>({
    mutationFn: (id: string) => approveRequest(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["pending"] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}

/** Mutation: deny a pending request. */
export function useDenyRequest() {
  const queryClient = useQueryClient();

  return useMutation<
    CommandResponse,
    Error,
    { id: string; reason?: string }
  >({
    mutationFn: ({ id, reason }) => denyRequest(id, reason),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["pending"] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}

/** Mutation: send text input to an agent. */
export function useSendInput() {
  return useMutation<CommandResponse, Error, string>({
    mutationFn: (text: string) => sendInput(text),
  });
}

/** Mutation: start an agent. */
export function useStartAgent() {
  const queryClient = useQueryClient();

  return useMutation<CommandResponse, Error, string>({
    mutationFn: (name: string) => startAgent(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}

/** Mutation: stop an agent. */
export function useStopAgent() {
  const queryClient = useQueryClient();

  return useMutation<CommandResponse, Error, string>({
    mutationFn: (name: string) => stopAgent(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}

/** Mutation: restart an agent. */
export function useRestartAgent() {
  const queryClient = useQueryClient();

  return useMutation<CommandResponse, Error, string>({
    mutationFn: (name: string) => restartAgent(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });
}
