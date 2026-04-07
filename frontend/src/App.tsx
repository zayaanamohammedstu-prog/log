import { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider, CssBaseline, Box, CircularProgress } from '@mui/material'
import { AuthProvider, useAuth } from './context/AuthContext'
import { darkTheme, lightTheme } from './theme'
import Layout from './components/Layout'
import RoleGuard from './components/RoleGuard'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import AuditorWorkbench from './pages/AuditorWorkbench'
import AdminDashboard from './pages/AdminDashboard'
import SuperAdminDashboard from './pages/SuperAdminDashboard'
import ViewerDashboard from './pages/ViewerDashboard'

function AppRoutes({ toggleTheme, isDark }: { toggleTheme: () => void; isDark: boolean }) {
  const { user, isAuthenticated, loading } = useAuth()
  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    )
  }
  const homePath = () => {
    if (!user) return '/login'
    if (user.role === 'super_admin') return '/super-admin'
    if (user.role === 'admin' || user.role === 'administrator') return '/admin'
    if (user.role === 'auditor') return '/auditor'
    return '/viewer'
  }
  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to={homePath()} replace /> : <LoginPage />} />
      <Route path="/register" element={isAuthenticated ? <Navigate to={homePath()} replace /> : <RegisterPage />} />
      <Route path="/auditor" element={
        <RoleGuard allowedRoles={['auditor','admin','administrator','super_admin']}>
          <Layout toggleTheme={toggleTheme} isDark={isDark}><AuditorWorkbench /></Layout>
        </RoleGuard>
      } />
      <Route path="/admin" element={
        <RoleGuard allowedRoles={['admin','administrator','super_admin']}>
          <Layout toggleTheme={toggleTheme} isDark={isDark}><AdminDashboard /></Layout>
        </RoleGuard>
      } />
      <Route path="/super-admin" element={
        <RoleGuard allowedRoles={['super_admin']}>
          <Layout toggleTheme={toggleTheme} isDark={isDark}><SuperAdminDashboard /></Layout>
        </RoleGuard>
      } />
      <Route path="/viewer" element={
        <RoleGuard allowedRoles={['viewer','auditor','admin','administrator','super_admin']}>
          <Layout toggleTheme={toggleTheme} isDark={isDark}><ViewerDashboard /></Layout>
        </RoleGuard>
      } />
      <Route path="*" element={<Navigate to={isAuthenticated ? homePath() : '/login'} replace />} />
    </Routes>
  )
}

export default function App() {
  const [isDark, setIsDark] = useState(true)
  return (
    <ThemeProvider theme={isDark ? darkTheme : lightTheme}>
      <CssBaseline />
      <AuthProvider>
        <BrowserRouter basename="/react">
          <AppRoutes toggleTheme={() => setIsDark(d => !d)} isDark={isDark} />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}
