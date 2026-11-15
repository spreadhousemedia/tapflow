import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { Session, User } from '@supabase/supabase-js'
import { supabase } from '../lib/supabase'

interface AuthContextValue {
  user: User | null
  session: Session | null
  loading: boolean
  signIn: (email: string, password: string) => Promise<{ error: string | null }>
  signOut: () => Promise<void>
}

const SESSION_KEY = 'spreadnfc_admin_session'

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // 1. Check persisted Supabase session in localStorage
    const savedSessionStr = localStorage.getItem(SESSION_KEY)
    if (savedSessionStr) {
      try {
        const parsed = JSON.parse(savedSessionStr)
        const savedAt = new Date(parsed.saved_at || 0).getTime()
        // Valid for 7 days
        if (Date.now() - savedAt < 7 * 24 * 60 * 60 * 1000) {
          setSession(parsed.session)
          setLoading(false)
        }
      } catch {
        localStorage.removeItem(SESSION_KEY)
      }
    }

    // 2. Also check Supabase active session
    supabase.auth.getSession().then(({ data }) => {
      if (data?.session) {
        setSession(data.session)
      }
      setLoading(false)
    }).catch(() => {
      setLoading(false)
    })

    const { data: listener } = supabase.auth.onAuthStateChange((_event, newSession) => {
      if (newSession) {
        setSession(newSession)
      } else {
        // Session expired or signed out on another tab
        setSession(null)
        localStorage.removeItem(SESSION_KEY)
      }
    })

    return () => listener.subscription.unsubscribe()
  }, [])

  async function signIn(email: string, password: string) {
    const cleanEmail = email.trim().toLowerCase()
    const cleanPassword = password.trim()

    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: cleanEmail,
        password: cleanPassword,
      })

      if (!error && data?.session) {
        setSession(data.session)
        localStorage.setItem(SESSION_KEY, JSON.stringify({
          session: data.session,
          saved_at: new Date().toISOString(),
        }))
        return { error: null }
      }

      return { error: 'Invalid email or password.' }
    } catch {
      return { error: 'Unable to connect. Please check your connection and try again.' }
    }
  }

  async function signOut() {
    localStorage.removeItem(SESSION_KEY)
    try {
      await supabase.auth.signOut()
    } catch {
      // ignore network errors on sign-out
    }
    setSession(null)
  }

  return (
    <AuthContext.Provider value={{ user: session?.user ?? null, session, loading, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
