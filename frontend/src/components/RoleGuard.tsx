import React, { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Box, CircularProgress } from '@mui/material'

const ROLE_HIERARCHY: Record<string, number> = {
  viewer: 1,
  auditor: 2,
  admin: 3,
  super_admin: 4,
}

interface RoleGuardProps {
  children: ReactNode
  minRole?: string
  allowedRoles?: string[]
}

export default function RoleGuard({ children, minRole, allowedRoles }: RoleGuardProps) {
  const { user, isAuthenticated, loading } = useAuth()

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    )
  }

  if (!isAuthenticated) return <Navigate to="/login" replace />

  if (minRole && user) {
    if ((ROLE_HIERARCHY[user.role] || 0) < (ROLE_HIERARCHY[minRole] || 0)) {
      return <Navigate to="/dashboard" replace />
    }
  }

  if (allowedRoles && user) {
    if (!allowedRoles.includes(user.role)) {
      return <Navigate to="/dashboard" replace />
    }
  }

  return <>{children}</>
}
