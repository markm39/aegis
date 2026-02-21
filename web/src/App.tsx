/**
 * Main application component with React Router setup.
 *
 * Routes:
 * - / : Fleet dashboard
 * - /agents/:name : Agent detail page
 * - /pending : Pending approvals page
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { AgentDetail } from "./pages/AgentDetail";
import { Dashboard } from "./pages/Dashboard";
import { Pending } from "./pages/Pending";
import "./App.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 3_000,
      retry: 2,
      refetchOnWindowFocus: true,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agents/:name" element={<AgentDetail />} />
          <Route path="/pending" element={<Pending />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
