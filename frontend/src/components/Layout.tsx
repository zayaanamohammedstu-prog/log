import React, { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  AppBar, Box, Drawer, IconButton, List, ListItemButton, ListItemIcon,
  ListItemText, Toolbar, Typography, Badge, Tooltip, Chip,
  Divider, Avatar, useTheme, useMediaQuery,
} from '@mui/material'
import MenuIcon from '@mui/icons-material/Menu'
import SecurityIcon from '@mui/icons-material/Security'
import PeopleIcon from '@mui/icons-material/People'
import AssessmentIcon from '@mui/icons-material/Assessment'
import LogoutIcon from '@mui/icons-material/Logout'
import NotificationsIcon from '@mui/icons-material/Notifications'
import Brightness4Icon from '@mui/icons-material/Brightness4'
import Brightness7Icon from '@mui/icons-material/Brightness7'
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings'
import ShieldIcon from '@mui/icons-material/Shield'
import VisibilityIcon from '@mui/icons-material/Visibility'
import SupervisorAccountIcon from '@mui/icons-material/SupervisorAccount'
import { useAuth } from '../context/AuthContext'
import { useSocket } from '../hooks/useSocket'

const DRAWER_WIDTH = 240

const ROLE_COLORS: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  super_admin: 'error',
  admin: 'warning',
  auditor: 'info',
  viewer: 'success',
}

interface LayoutProps {
  children: React.ReactNode
  toggleTheme: () => void
  isDark: boolean
}

export default function Layout({ children, toggleTheme, isDark }: LayoutProps) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  const [mobileOpen, setMobileOpen] = useState(false)
  const { alerts } = useSocket()

  const menuItems = React.useMemo(() => {
    const role = user?.role || 'viewer'
    const items: { label: string; icon: React.ReactNode; path: string }[] = []
    if (role === 'super_admin') {
      items.push({ label: 'Super Admin', icon: <SupervisorAccountIcon />, path: '/super-admin' })
    }
    if (role === 'super_admin' || role === 'admin') {
      items.push({ label: 'Admin Panel', icon: <AdminPanelSettingsIcon />, path: '/admin' })
    }
    if (['super_admin', 'admin', 'auditor'].includes(role)) {
      items.push({ label: 'Auditor Workbench', icon: <SecurityIcon />, path: '/auditor' })
    }
    items.push({ label: 'Reports', icon: <AssessmentIcon />, path: '/viewer' })
    return items
  }, [user?.role])

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', bgcolor: 'background.paper' }}>
      <Box sx={{ p: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
        <ShieldIcon color="primary" sx={{ fontSize: 32 }} />
        <Typography variant="h6" fontWeight={700} color="primary">LogGuard</Typography>
      </Box>
      <Divider />
      <List sx={{ flex: 1, pt: 1 }}>
        {menuItems.map(item => (
          <ListItemButton
            key={item.path}
            selected={location.pathname === item.path}
            onClick={() => { navigate(item.path); if (isMobile) setMobileOpen(false) }}
            sx={{ borderRadius: 1, mx: 1, mb: 0.5 }}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>{item.icon}</ListItemIcon>
            <ListItemText primary={item.label} />
          </ListItemButton>
        ))}
      </List>
      <Divider />
      <Box sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main', fontSize: 14 }}>
            {user?.username?.[0]?.toUpperCase() || 'U'}
          </Avatar>
          <Box>
            <Typography variant="body2" fontWeight={600}>{user?.username}</Typography>
            <Chip
              label={user?.role}
              size="small"
              color={ROLE_COLORS[user?.role || 'viewer'] || 'default'}
              sx={{ height: 16, fontSize: 10 }}
            />
          </Box>
        </Box>
        <ListItemButton onClick={() => { logout(); navigate('/login') }} sx={{ borderRadius: 1 }}>
          <ListItemIcon sx={{ minWidth: 40 }}><LogoutIcon /></ListItemIcon>
          <ListItemText primary="Logout" />
        </ListItemButton>
      </Box>
    </Box>
  )

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AppBar
        position="fixed"
        sx={{ zIndex: theme.zIndex.drawer + 1, bgcolor: 'background.paper', borderBottom: '1px solid', borderColor: 'divider' }}
        elevation={0}
      >
        <Toolbar>
          {isMobile && (
            <IconButton edge="start" onClick={() => setMobileOpen(!mobileOpen)} sx={{ mr: 2 }}>
              <MenuIcon />
            </IconButton>
          )}
          <ShieldIcon color="primary" sx={{ mr: 1 }} />
          <Typography variant="h6" fontWeight={700} color="primary" sx={{ flexGrow: 1 }}>
            LogGuard
          </Typography>
          <Tooltip title="Toggle theme">
            <IconButton onClick={toggleTheme} size="small" sx={{ mr: 1 }}>
              {isDark ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
          </Tooltip>
          <Tooltip title={`${alerts.length} real-time alerts`}>
            <IconButton size="small" sx={{ mr: 1 }}>
              <Badge badgeContent={alerts.length} color="error" max={99}>
                <NotificationsIcon />
              </Badge>
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      {isMobile ? (
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{ '& .MuiDrawer-paper': { width: DRAWER_WIDTH } }}
        >
          {drawer}
        </Drawer>
      ) : (
        <Drawer
          variant="permanent"
          sx={{ width: DRAWER_WIDTH, flexShrink: 0, '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' } }}
        >
          {drawer}
        </Drawer>
      )}

      <Box component="main" sx={{ flexGrow: 1, p: 3, mt: 8, bgcolor: 'background.default', minHeight: '100vh' }}>
        {children}
      </Box>
    </Box>
  )
}
