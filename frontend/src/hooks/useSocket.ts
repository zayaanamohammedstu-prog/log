import { io, Socket } from 'socket.io-client'
import { useEffect, useState } from 'react'

export function useSocket() {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [alerts, setAlerts] = useState<any[]>([])

  useEffect(() => {
    const s = io('/', {
      extraHeaders: {
        Authorization: `Bearer ${localStorage.getItem('logguard_token') || ''}`
      }
    })
    s.on('connect', () => {
      s.emit('join_audit_room', { room: 'audit_room' })
    })
    s.on('new_analysis', (data: any) => {
      setAlerts(prev => [data, ...prev].slice(0, 50))
    })
    setSocket(s)
    return () => { s.disconnect() }
  }, [])

  return { socket, alerts }
}
