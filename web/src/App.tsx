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

import { LanguageSelector } from "./components/LanguageSelector";
import { useDirection } from "./hooks/useDirection";
import { AgentDetail } from "./pages/AgentDetail";
import { Dashboard } from "./pages/Dashboard";
import { Pending } from "./pages/Pending";
import "./i18n";
import "./App.css";
import "./styles/rtl.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 3_000,
      retry: 2,
      refetchOnWindowFocus: true,
    },
  },
});

function AppLayout() {
  useDirection();

  return (
    <>
      <div
        style={{
          position: "fixed",
          top: "8px",
          insetInlineEnd: "16px",
          zIndex: 1000,
        }}
      >
        <LanguageSelector />
      </div>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/agents/:name" element={<AgentDetail />} />
        <Route path="/pending" element={<Pending />} />
      </Routes>
    </>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppLayout />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
