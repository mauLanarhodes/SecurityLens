import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { ApiError } from "./api";
import "./index.css";

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 15000,
      staleTime: 5000,
      retry: (failures, error) => !(error instanceof ApiError && (error.status === 401 || error.status === 403))
        && error.name !== "AbortError" && failures < 2,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
);
