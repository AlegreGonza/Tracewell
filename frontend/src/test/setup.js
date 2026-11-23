import "@testing-library/jest-dom/vitest";
import React from "react";
import { vi } from "vitest";
import { MantineProvider } from "@mantine/core";
import { theme } from "../theme.js";

// Mantine necesita APIs del navegador que jsdom no trae.
if (!window.matchMedia) {
  window.matchMedia = (query) => ({
    matches: false, media: query, onchange: null,
    addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {}, dispatchEvent: () => false,
  });
}
if (!window.ResizeObserver) {
  window.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
}

// Todos los tests renderizan dentro del MantineProvider, como en la aplicación real
vi.mock("@testing-library/react", async (importOriginal) => {
  const actual = await importOriginal();
  const wrapper = ({ children }) => React.createElement(MantineProvider, { theme, env: "test", withCssVariables: false, withGlobalClasses: false }, children);
  return { ...actual, render: (ui, options) => actual.render(ui, { wrapper, ...options }) };
});
