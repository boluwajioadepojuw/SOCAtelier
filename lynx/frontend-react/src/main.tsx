import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ConfigProvider, theme } from 'antd'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
})

// Lynx night palette: warm near-black surfaces, amber primary, cyan secondary.
// Amber is the interactive accent; severity colors stay red/orange/green.
const lynxTheme = {
  algorithm: theme.darkAlgorithm,
  token: {
    colorBgBase: '#0a0908',
    colorBgContainer: '#14110d',
    colorBgElevated: '#1a1510',
    colorBorder: '#2b251c',
    colorBorderSecondary: '#2b251c',
    colorText: '#e9e3d6',
    colorTextSecondary: '#938a76',
    colorTextTertiary: '#4d463a',
    colorPrimary: '#e0a23c',
    colorError: '#e5534b',
    colorWarning: '#d29922',
    colorSuccess: '#4fae74',
    colorLink: '#e0a23c',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    fontSize: 13,
    borderRadius: 4,
    borderRadiusSM: 4,
    lineHeight: 1.5,
    controlHeight: 32,
    controlHeightSM: 24,
  },
  components: {
    Table: {
      headerBg: '#14110d',
      headerColor: '#938a76',
      rowHoverBg: '#1a1510',
      borderColor: '#2b251c',
      cellPaddingBlock: 8,
      cellPaddingInline: 14,
      headerBorderRadius: 0,
    },
    Badge: {
      colorBorderBg: 'transparent',
    },
    Tag: {
      defaultBg: 'rgba(43,37,28,0.8)',
      defaultColor: '#938a76',
    },
    Button: {
      defaultBg: 'transparent',
      defaultBorderColor: '#2b251c',
      defaultColor: '#938a76',
    },
    Card: {
      colorBgContainer: '#14110d',
      colorBorderSecondary: '#2b251c',
    },
    Layout: {
      headerBg: '#14110d',
      siderBg: '#14110d',
      bodyBg: '#0a0908',
      triggerBg: '#1a1510',
    },
    Menu: {
      darkItemBg: '#14110d',
      darkItemColor: '#938a76',
      darkItemHoverColor: '#e9e3d6',
      darkItemSelectedColor: '#e0a23c',
      darkItemSelectedBg: 'rgba(224,162,60,0.10)',
      itemHeight: 48,
    },
    Select: {
      colorBgContainer: '#1a1510',
      colorBorder: '#2b251c',
    },
    Input: {
      colorBgContainer: '#1a1510',
      colorBorder: '#2b251c',
      activeBorderColor: '#e0a23c',
    },
  },
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ConfigProvider theme={lynxTheme}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ConfigProvider>
    </QueryClientProvider>
  </StrictMode>
)
